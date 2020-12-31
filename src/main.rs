use eyre::{eyre, Result};
use goblin::{peek_bytes, Hint};
use objpoke::elf;
use regex::Regex;
use std::convert::TryInto;
use std::fs;
use std::path::{Path, PathBuf};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "objpoke")]
struct Opt {
    /// Accepts regexes of the symbol names to keep global, and localizes the rest
    #[structopt(short, long, number_of_values = 1)]
    keep_symbols: Vec<String>,

    /// Input object
    #[structopt(name = "input", parse(from_os_str))]
    input: PathBuf,

    /// Output object
    #[structopt(name = "output", parse(from_os_str))]
    output: PathBuf,
}

fn main() -> Result<()> {
    let opt = Opt::from_args();
    if opt.keep_symbols.is_empty() {
        return Err(eyre!("No symbol filter specified"));
    }
    let keep_regexes = opt
        .keep_symbols
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
            Hint::Elf(_) => elf::localize_elf_symbols(data, &keep_regexes)?,
            Hint::Mach(_) | Hint::MachFat(_) => return Err(eyre!("Cannot handle mach objects")),
            Hint::PE => return Err(eyre!("Cannot handle PE objects")),
            _ => return Err(eyre!("Unknown input file type")),
        }
    } else {
        return Err(eyre!("Input object is too small"));
    };

    fs::write(opt.output, new_data)?;
    Ok(())
}
