mod reloc;
mod symtab;

use crate::elf::reloc::{rel_size, ElfRelocationUpdate};
use crate::elf::symtab::{sym_size, ElfSymbolTableUpdate};
use eyre::{eyre, Result};
use goblin::container::{Container, Ctx};
use goblin::elf::section_header::{
    section_header32, section_header64, SHT_GNU_HASH, SHT_GNU_VERSYM, SHT_HASH, SHT_NULL, SHT_RELA,
    SHT_SYMTAB_SHNDX,
};
use goblin::elf::{Elf, Header, SectionHeaders, Sym};
use goblin::elf32::section_header::SHT_GROUP;
use goblin::strtab::Strtab;
use regex::Regex;
use scroll::ctx::IntoCtx;
use scroll::{Pread, Pwrite};
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

    patch_new_elf_symbols(
        elf.header,
        section_headers,
        ctx,
        data,
        new_symtabs,
        new_relocs,
    )
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

    for (sh_idx, mut header) in section_headers.into_iter().enumerate() {
        // We don't implement hash sections, but they're just an optimization. Discard them.
        if header.sh_type == SHT_HASH || header.sh_type == SHT_GNU_HASH {
            header.sh_type = SHT_NULL;
        } else if header.sh_type == SHT_SYMTAB_SHNDX {
            // We *could* handle those by just reordering the entries
            return Err(eyre!("Cannot handle SYMTAB_SHNDX ELF sections"));
        } else if header.sh_type == SHT_GNU_VERSYM {
            // We could handle those by reordering the entries, but it's not always enough
            // If we're trying to localize a versioned symbol, we'd need to modify other sections
            return Err(eyre!("Cannot handle GNU_VERSYM ELF sections"));
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
        if header.sh_type != SHT_GROUP || header.sh_flags != 0 {
            continue;
        }

        let group_range = header.file_range();
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
            return Err(eyre!(
                "COMDAT section group also contains unknown flags ({}), refusing to continue",
                group_flags
            ));
        }

        let symtab_idx = header.sh_link as usize;
        let sym_idx = header.sh_info as usize;

        let symtab = match section_headers.get(symtab_idx) {
            Some(symtab) => symtab,
            None => {
                return Err(eyre!(
                    "Section group references invalid symbol table index: {}",
                    symtab_idx
                ));
            }
        };
        let symtab_range = symtab.file_range();
        let symtab_data = &data[symtab_range.start..symtab_range.end];
        let sym_size = sym_size(&ctx);
        let name_sym: Sym = symtab_data.pread_with(sym_idx * sym_size, ctx).unwrap();
        let strtab_idx = symtab.sh_link as usize;

        let strtab = if strtab_idx >= section_headers.len() {
            return Err(eyre!(
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
