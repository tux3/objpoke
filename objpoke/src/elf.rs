mod reloc;
mod symtab;

use crate::elf::{
    reloc::{rel_size, ElfRelocationUpdate},
    symtab::{sym_size, ElfSymbolTableUpdate},
};
use anyhow::{anyhow, bail, Result};
use goblin::{
    container::{Container, Ctx},
    elf::{
        section_header::{
            section_header32, section_header64, SHT_GNU_HASH, SHT_GNU_VERSYM, SHT_HASH, SHT_NULL, SHT_RELA,
            SHT_SYMTAB_SHNDX,
        },
        Elf, Header, SectionHeaders, Sym,
    },
    elf32::section_header::SHT_GROUP,
    strtab::Strtab,
};
use regex::Regex;
use scroll::{ctx::IntoCtx, Pread, Pwrite};
use std::collections::HashMap;

const GRP_COMDAT: u32 = 1; // Per https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter7-26.html

pub fn localize_elf_symbols(data: Vec<u8>, keep_regexes: &[Regex]) -> Result<Vec<u8>> {
    let elf = Elf::parse(&data)?;
    let container = elf.header.container()?;
    let endianness = elf.header.endianness()?;
    let ctx = Ctx::new(container, endianness);
    let section_headers = elf.section_headers.clone();

    let new_symtabs = symtab::localize_elf_symbols(&elf, ctx, &data, keep_regexes)?;
    let new_relocs = reloc::process_elf_relocations(&elf, ctx, &data, &new_symtabs);

    patch_new_elf_symbols(elf.header, section_headers, ctx, data, new_symtabs, new_relocs)
}

fn patch_new_elf_symbols(
    elf_header: Header,
    section_headers: SectionHeaders,
    ctx: Ctx,
    mut data: Vec<u8>,
    mut new_symtabs: HashMap<usize, ElfSymbolTableUpdate>,
    mut new_relocs: HashMap<usize, ElfRelocationUpdate>,
) -> Result<Vec<u8>> {
    let shoff = elf_header.e_shoff as usize;
    let sym_size = sym_size(&ctx);
    let header_size = match ctx.container {
        Container::Little => section_header32::SIZEOF_SHDR,
        Container::Big => section_header64::SIZEOF_SHDR,
    };
    let mut shndx_to_symtab_map = HashMap::<usize, HashMap<usize, usize>>::new();

    for (sh_idx, header) in section_headers.iter().enumerate() {
        if header.sh_type == SHT_SYMTAB_SHNDX {
            if header.sh_info != 0 {
                bail!("SYMTAB_SHNDX ELF section has invalid non-zero sh_info");
            }
            match new_symtabs.get_mut(&(header.sh_link as usize)) {
                None => bail!("SYMTAB_SHNDX ELF section references invalid symtab in sh_link"),
                Some(symtab) => shndx_to_symtab_map.insert(sh_idx, std::mem::take(&mut symtab.sym_idx_map)),
            };
        }
    }

    for (sh_idx, mut header) in section_headers.into_iter().enumerate() {
        // We don't implement hash sections, but they're just an optimization. Discard them.
        if header.sh_type == SHT_HASH || header.sh_type == SHT_GNU_HASH {
            header.sh_type = SHT_NULL;
        } else if header.sh_type == SHT_SYMTAB_SHNDX {
            // SYMTAB_SHNDX entries match the symtab entry order 1:1, so we just apply the same swaps
            let symtab_idx_map = shndx_to_symtab_map.get(&sh_idx).unwrap();
            let shndx_range = header.file_range().expect("Symtab SHNDX without file range");
            let shndx_data = &mut data[shndx_range.start..shndx_range.end];
            for (old_idx, new_idx) in symtab_idx_map {
                if old_idx < new_idx {
                    let old_entry: u32 = shndx_data.pread_with(old_idx * 4, ctx.le).unwrap();
                    let new_entry: u32 = shndx_data.pread_with(new_idx * 4, ctx.le).unwrap();
                    shndx_data.pwrite_with(new_entry, old_idx * 4, ctx.le)?;
                    shndx_data.pwrite_with(old_entry, new_idx * 4, ctx.le)?;
                }
            }
        } else if header.sh_type == SHT_GNU_VERSYM {
            // We could handle those by reordering the entries, but it's not always enough
            // If we're trying to localize a versioned symbol, we'd need to modify other sections
            return Err(anyhow!("Cannot handle GNU_VERSYM ELF sections"));
        } else if let Some(new_symtab) = new_symtabs.remove(&sh_idx) {
            for (sym_idx, sym) in new_symtab.syms.into_iter().enumerate() {
                let offset = new_symtab.header.sh_offset as usize + sym_idx * sym_size;
                sym.into_ctx(&mut data[offset..], ctx);
            }
            header = new_symtab.header;
        } else if let Some(new_rel) = new_relocs.remove(&sh_idx) {
            let is_rela = new_rel.header.sh_type == SHT_RELA;
            let rel_size = rel_size(ctx, &new_rel.header);
            for (rel_idx, rel) in new_rel.rels.into_iter().enumerate() {
                let offset = new_rel.header.sh_offset as usize + rel_idx * rel_size;
                rel.into_ctx(&mut data[offset..], (is_rela, ctx));
            }
        }

        let offset = shoff + sh_idx * header_size;
        header.into_ctx(&mut data[offset..], ctx);
    }

    Ok(data)
}

pub fn demote_comdat_groups(mut data: Vec<u8>, keep_regexes: &[Regex]) -> Result<Vec<u8>> {
    let elf = Elf::parse(&data)?;
    let container = elf.header.container()?;
    let endianness = elf.header.endianness()?;
    let section_headers = elf.section_headers;
    let ctx = Ctx::new(container, endianness);

    'next_section: for header in section_headers.iter() {
        // "The sh_flags member of the section header contains the value zero."
        if header.sh_type != SHT_GROUP || header.sh_flags != 0 {
            continue;
        }

        let group_range = header.file_range().expect("Section header without file range");
        let group_data = &data[group_range.start..group_range.end];
        if group_data.len() < 4 {
            continue; // Not Supposed To Happen, but can't be too careful with wild ELFs...
        }
        let group_flags: u32 = group_data.pread_with(0, endianness).unwrap();
        if group_flags & GRP_COMDAT == 0 {
            continue;
        }
        if group_flags != GRP_COMDAT {
            // It's probably safe to unset just GRP_COMDAT, but I can't rule out that someone
            // will create a new flag that _only_ makes sense alongside GRP_COMDAT,
            // so out of an abundance of caution let's reject unknown group flags
            return Err(anyhow!(
                "COMDAT section group also contains unknown flags ({}), refusing to continue",
                group_flags
            ));
        }

        // "The section header of the SHT_GROUP section specifies the identifying symbol entry.
        //  The sh_link member contains the section header index of the symbol table section that contains the entry.
        //  The sh_info member contains the symbol table index of the identifying entry"
        let symtab_idx = header.sh_link as usize;
        let sym_idx = header.sh_info as usize;

        let symtab = match section_headers.get(symtab_idx) {
            Some(symtab) => symtab,
            None => {
                return Err(anyhow!(
                    "Section group references invalid symbol table index: {}",
                    symtab_idx
                ));
            },
        };
        let symtab_range = symtab.file_range().expect("Symtab section without file range");
        let symtab_data = &data[symtab_range.start..symtab_range.end];
        let sym_size = sym_size(&ctx);
        let name_sym: Sym = symtab_data.pread_with(sym_idx * sym_size, ctx).unwrap();
        let strtab_idx = symtab.sh_link as usize;

        let strtab = if strtab_idx >= section_headers.len() {
            return Err(anyhow!(
                "Section group symbol references invalid string table index: {}",
                strtab_idx
            ));
        } else {
            let shdr = &section_headers[strtab_idx];
            shdr.check_size(data.len())?;
            Strtab::parse(&data, shdr.sh_offset as usize, shdr.sh_size as usize, 0x0)
        }?;

        if let Some(Ok(name)) = strtab.get(name_sym.st_name) {
            for regex in keep_regexes {
                if regex.is_match(name) {
                    continue 'next_section;
                }
            }
        } else {
            continue 'next_section;
        }

        let demoted_flags = group_flags & !GRP_COMDAT;
        data.pwrite_with(demoted_flags, group_range.start, endianness)?;
    }

    Ok(data)
}
