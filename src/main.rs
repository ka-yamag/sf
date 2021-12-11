mod error;
mod aes_cbc;
mod util;

use std::path::PathBuf;
use structopt::StructOpt;
use console::style;

use crate::aes_cbc::{Cryptgraphy, AESCBC};
use crate::error::{SfResult, SfError};

#[derive(StructOpt)]
#[structopt(rename_all = "kebab-case")]
pub struct Opt {
    /// Action
    #[structopt(short, long)]
    action: String,

    /// Password
    #[structopt(short, long)]
    pass: String,

    /// The number of thread
    #[structopt(short="n", long="num-threads")]
    thread: Option<i32>,

    /// Target file format
    #[structopt(short="f", long)]
    target_file_format: Option<String>,

    /// Input dir
    #[structopt(short, long, parse(from_os_str))]
    input: PathBuf,

    /// Output dir
    #[structopt(short, long, parse(from_os_str))]
    output: PathBuf,
}

fn main() -> SfResult {
    let mut opt = Opt::from_args();

    if !opt.input.is_dir() || !opt.output.is_dir() {
        return Err(SfError::new("input or output is not directory".to_string()))
    }

    if opt.pass == "" {
        return Err(SfError::new("key is empty".to_string()))
    }

    if opt.thread.is_none() {
        opt.thread = Some(1);
    }

    let cipher: AESCBC = Cryptgraphy::new(&opt);

    match opt.action.as_str() {
        "encrypt" => {
            println!(
                "{} {}",
                style("[+]").bold().cyan(),
                style("Encrypt mode").bold().green(),
                );
            cipher.encrypt()?
        },
        "decrypt" => {
            println!(
                "{} {}",
                style("[+]").bold().cyan(),
                style("Decrypt mode").bold().green(),
                );
            cipher.decrypt()?
        },
        _ => return Err(SfError::new(format!("Not defined action: {}", opt.action)))
    }

    Ok(())
}
