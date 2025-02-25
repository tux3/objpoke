use anyhow::{anyhow, Result};
use clap::Parser;
use goblin::{peek_bytes, Hint};
use objpoke::elf;
use regex::Regex;
use std::{
    convert::TryInto,
    fs,
    path::{Path, PathBuf},
};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Opt {
    /// Accepts regexes of the symbol names to keep global, and localizes the rest
    #[arg(short, long, num_args = 1)]
    keep_symbols: Vec<String>,

    /// Accepts regexes of the GRP_COMDAT section groups to keep, the rest becomes regular groups
    #[arg(long, num_args = 1)]
    keep_comdat_sections: Vec<String>,

    /// Input object
    input: PathBuf,

    /// Output object
    output: PathBuf,
}

fn main() -> Result<()> {
    let opt = Opt::parse();
    if opt.keep_symbols.is_empty() && opt.keep_comdat_sections.is_empty() {
        return Err(anyhow!("No action specified"));
    }
    let keep_regexes = opt
        .keep_symbols
        .into_iter()
        .map(|r| Regex::new(&r))
        .collect::<Result<Vec<_>, _>>()?;
    let keep_comdat_regexes = opt
        .keep_comdat_sections
        .into_iter()
        .map(|r| Regex::new(&r))
        .collect::<Result<Vec<_>, _>>()?;

    let path = Path::new(&opt.input);
    let data = fs::read(path)?;

    let hint_bytes = data
        .get(0..16)
        .and_then(|hint_bytes_slice| hint_bytes_slice.try_into().ok());
    let new_data = if let Some(hint_bytes) = hint_bytes {
        match peek_bytes(hint_bytes)? {
            Hint::Elf(_) => {
                let mut patched_data = data;
                if !keep_regexes.is_empty() {
                    patched_data = elf::localize_elf_symbols(patched_data, &keep_regexes)?
                }
                if !keep_comdat_regexes.is_empty() {
                    patched_data = elf::demote_comdat_groups(patched_data, &keep_comdat_regexes)?
                }
                patched_data
            },
            Hint::Mach(_) | Hint::MachFat(_) => return Err(anyhow!("Cannot handle mach objects")),
            Hint::PE => return Err(anyhow!("Cannot handle PE objects")),
            _ => return Err(anyhow!("Unknown input file type")),
        }
    } else {
        return Err(anyhow!("Input object is too small"));
    };

    fs::write(opt.output, new_data)?;
    Ok(())
}
