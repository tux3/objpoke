use eyre::{eyre, Result};
use goblin::container::{Container, Ctx};
use goblin::elf::reloc::{reloc32, reloc64};
use goblin::elf::section_header::{
    section_header32, section_header64, SHT_GNU_HASH, SHT_GNU_VERSYM, SHT_HASH, SHT_NULL, SHT_REL,
    SHT_RELA, SHT_SYMTAB, SHT_SYMTAB_SHNDX,
};
use goblin::elf::sym::{
    sym32, sym64, Sym, STB_GNU_UNIQUE, STB_LOCAL, STT_COMMON, STT_FUNC, STT_NOTYPE, STT_OBJECT,
};
use goblin::elf::{Elf, Reloc, SectionHeader};
use goblin::strtab::Strtab;
use regex::Regex;
use scroll::ctx::IntoCtx;
use scroll::Pread;
use std::collections::HashMap;

pub struct ElfRelocationUpdate {
    pub header: SectionHeader,
    pub rels: Vec<Reloc>,
}

pub struct ElfSymbolTableUpdate {
    pub header: SectionHeader,
    pub syms: Vec<Sym>,
    pub sym_idx_map: HashMap<usize, usize>,
}

fn rel_size(ctx: Ctx, section: &SectionHeader) -> usize {
    match ctx.container {
        Container::Little => {
            if section.sh_type == SHT_RELA {
                reloc32::SIZEOF_RELA
            } else {
                reloc32::SIZEOF_REL
            }
        }
        Container::Big => {
            if section.sh_type == SHT_RELA {
                reloc64::SIZEOF_RELA
            } else {
                reloc64::SIZEOF_REL
            }
        }
    }
}

fn process_syms(
    ctx: Ctx,
    syms_data: &[u8],
    count: usize,
    orig_header: &SectionHeader,
    strtab: Strtab,
    keep_regexes: &[Regex],
) -> ElfSymbolTableUpdate {
    let sym_size = match ctx.container {
        Container::Little => sym32::SIZEOF_SYM,
        Container::Big => sym64::SIZEOF_SYM,
    };
    let mut first_nonlocal_idx = orig_header.sh_info as usize;

    let mut syms = Vec::<Sym>::new();
    let mut sym_idx_map = HashMap::<usize, usize>::new();

    for idx in 0..count {
        syms.push(syms_data.pread_with(idx * sym_size, ctx).unwrap());
    }

    'next_symbol: for (idx, sym) in syms
        .iter_mut()
        .enumerate()
        .skip(first_nonlocal_idx as usize)
    {
        #[allow(clippy::match_like_matches_macro)]
        let is_code_or_data = match sym.st_type() {
            STT_NOTYPE => false,             // Likely an undefined symbol
            STT_FUNC => true,                // Code
            STT_OBJECT | STT_COMMON => true, // Data
            _ => false,
        };
        let is_undef = sym.st_shndx == 0;
        if sym.st_name == 0 || is_undef || !is_code_or_data {
            continue;
        }
        if let Some(Ok(name)) = strtab.get(sym.st_name) {
            for regex in keep_regexes {
                if regex.is_match(name) {
                    continue 'next_symbol;
                }
            }
        } else {
            continue 'next_symbol;
        }

        // STB_GNU_UNIQUE is a hack to bypass RTLD_LOCAL
        // Apparently very few people understand exactly the semantics of GNU_UNIQUE,
        // but objcopy refuses to localize it so we won't either.
        if sym.st_bind() == STB_GNU_UNIQUE {
            continue 'next_symbol;
        }

        // Turn the symbol local
        sym.st_info = (STB_LOCAL << 4) | sym.st_type();

        // The symbol table must stay partitioned, with all locals first
        if idx > first_nonlocal_idx {
            sym_idx_map.insert(idx, first_nonlocal_idx);
            sym_idx_map.insert(first_nonlocal_idx, idx);
        }
        first_nonlocal_idx += 1;
    }

    for (old_idx, new_idx) in &sym_idx_map {
        if old_idx < new_idx {
            syms.swap(*old_idx, *new_idx);
        }
    }

    let mut header = orig_header.clone();
    header.sh_info = first_nonlocal_idx as u32;
    ElfSymbolTableUpdate {
        header,
        syms,
        sym_idx_map,
    }
}

fn process_elf_symtabs(
    elf: &Elf,
    ctx: Ctx,
    data: &[u8],
    keep_regexes: &[Regex],
) -> Result<HashMap<usize, ElfSymbolTableUpdate>> {
    let mut symtab_updates = HashMap::<usize, ElfSymbolTableUpdate>::new();
    for (idx, section) in elf.section_headers.iter().enumerate() {
        if section.sh_type == SHT_SYMTAB {
            let size = section.sh_entsize;
            let count = if size == 0 { 0 } else { section.sh_size / size };

            let strtab_idx = section.sh_link as usize;
            let strtab = if strtab_idx >= elf.section_headers.len() {
                return Err(eyre!(
                    "Symbol table references invalid string table index: {}",
                    strtab_idx
                ));
            } else {
                let shdr = &elf.section_headers[strtab_idx];
                shdr.check_size(data.len())?;
                Strtab::parse(data, shdr.sh_offset as usize, shdr.sh_size as usize, 0x0)
            }?;

            let range = section.file_range();
            let syms_data = &data[range.start..range.end];
            let update = process_syms(
                ctx,
                syms_data,
                count as usize,
                section,
                strtab,
                keep_regexes,
            );
            symtab_updates.insert(idx, update);
        }
    }
    Ok(symtab_updates)
}

fn process_elf_rel(
    ctx: Ctx,
    rel_data: &[u8],
    count: usize,
    rel_size: usize,
    header: &SectionHeader,
    symtab: &ElfSymbolTableUpdate,
) -> ElfRelocationUpdate {
    let mut rels = Vec::<Reloc>::new();

    let is_rela = header.sh_type == SHT_RELA;
    for idx in 0..count {
        rels.push(rel_data.pread_with(idx * rel_size, (is_rela, ctx)).unwrap());
    }

    for rel in rels.iter_mut() {
        if let Some(new_idx) = symtab.sym_idx_map.get(&rel.r_sym) {
            rel.r_sym = *new_idx;
        }
    }

    ElfRelocationUpdate {
        header: header.clone(),
        rels,
    }
}

fn process_elf_relocations(
    elf: &Elf,
    ctx: Ctx,
    data: &[u8],
    symtab_updates: &HashMap<usize, ElfSymbolTableUpdate>,
) -> HashMap<usize, ElfRelocationUpdate> {
    let mut relocation_updates = HashMap::<usize, ElfRelocationUpdate>::new();
    for (idx, section) in elf.section_headers.iter().enumerate() {
        if section.sh_type != SHT_REL && section.sh_type != SHT_RELA {
            continue;
        }

        // If the sh_link matches one of our re-ordered symtabs, process it
        let symtab_update = match symtab_updates.get(&(section.sh_link as usize)) {
            Some(update) => update,
            None => continue,
        };
        if symtab_update.sym_idx_map.is_empty() {
            continue;
        }

        let rel_size = rel_size(ctx, section);
        let count = section.sh_size as usize / rel_size;

        let range = section.file_range();
        let rel_data = &data[range.start..range.end];
        let update = process_elf_rel(
            ctx,
            rel_data,
            count as usize,
            rel_size,
            section,
            symtab_update,
        );
        relocation_updates.insert(idx, update);
    }
    relocation_updates
}

pub fn patch_elf(mut data: Vec<u8>, keep_regexes: &[Regex]) -> Result<Vec<u8>> {
    let elf = Elf::parse(&data)?;
    let container = elf.header.container()?;
    let endianness = elf.header.endianness()?;
    let ctx = Ctx::new(container, endianness);

    let mut new_symtabs = process_elf_symtabs(&elf, ctx, &data, keep_regexes)?;
    let mut new_relocs = process_elf_relocations(&elf, ctx, &data, &new_symtabs);

    let shoff = elf.header.e_shoff as usize;
    let section_headers = elf.section_headers.clone();
    drop(elf);

    let header_size = match container {
        Container::Little => section_header32::SIZEOF_SHDR,
        Container::Big => section_header64::SIZEOF_SHDR,
    };
    let sym_size = match ctx.container {
        Container::Little => sym32::SIZEOF_SYM,
        Container::Big => sym64::SIZEOF_SYM,
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
