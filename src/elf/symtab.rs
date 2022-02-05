use std::collections::HashMap;

use eyre::eyre;
use goblin::container::{Container, Ctx};
use goblin::elf::section_header::SHT_SYMTAB;
use goblin::elf::sym::{
    sym32, sym64, Sym, STB_LOCAL, STT_COMMON, STT_FUNC, STT_NOTYPE, STT_OBJECT,
};
use goblin::elf::{Elf, SectionHeader};
use goblin::strtab::Strtab;
use regex::Regex;
use scroll::Pread;

pub struct ElfSymbolTableUpdate {
    pub header: SectionHeader,
    pub syms: Vec<Sym>,
    pub sym_idx_map: HashMap<usize, usize>,
}

pub fn sym_size(ctx: &Ctx) -> usize {
    match ctx.container {
        Container::Little => sym32::SIZEOF_SYM,
        Container::Big => sym64::SIZEOF_SYM,
    }
}

fn localize_symtab_symbols(
    ctx: Ctx,
    syms_data: &[u8],
    count: usize,
    orig_header: &SectionHeader,
    strtab: Strtab,
    keep_regexes: &[Regex],
) -> ElfSymbolTableUpdate {
    let sym_size = sym_size(&ctx);
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
        if let Some(name) = strtab.get_at(sym.st_name) {
            for regex in keep_regexes {
                if regex.is_match(name) {
                    continue 'next_symbol;
                }
            }
        } else {
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

pub fn localize_elf_symbols(
    elf: &Elf,
    ctx: Ctx,
    data: &[u8],
    keep_regexes: &[Regex],
) -> eyre::Result<HashMap<usize, ElfSymbolTableUpdate>> {
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

            let range = section.file_range().expect("Section without file range");
            let syms_data = &data[range.start..range.end];
            let update = localize_symtab_symbols(
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
