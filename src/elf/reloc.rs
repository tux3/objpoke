use std::collections::HashMap;

use goblin::container::{Container, Ctx};
use goblin::elf::reloc::{reloc32, reloc64};
use goblin::elf::section_header::{SHT_REL, SHT_RELA};
use goblin::elf::{Elf, Reloc, SectionHeader};
use scroll::Pread;

use crate::elf::symtab::ElfSymbolTableUpdate;

pub struct ElfRelocationUpdate {
    pub header: SectionHeader,
    pub rels: Vec<Reloc>,
}

pub fn rel_size(ctx: Ctx, section: &SectionHeader) -> usize {
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

fn process_elf_rel_section(
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

pub fn process_elf_relocations(
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
        let update = process_elf_rel_section(
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
