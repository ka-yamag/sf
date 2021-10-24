mod cryptography;
mod error;

use std::path::PathBuf;
use structopt::StructOpt;

use cryptography::cryptography::Cryptgraphy;
use cryptography::aes128cbc::AESCBC;
use error::{SfResult, SfError};

#[derive(StructOpt)]
pub struct Opt {
    /// Action
    #[structopt(short, long)]
    action: String,

    /// Password
    #[structopt(short, long)]
    pass: String,

    /// The number of thread
    #[structopt(default_value = "1", short, long)]
    threads: i32,

    /// File format
    #[structopt(long)]
    target_file_format: String,

    /// Input dir
    #[structopt(short, long, parse(from_os_str))]
    input: PathBuf,

    /// Output dir
    #[structopt(short, long, parse(from_os_str), required_if("out", "dir"))]
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

    if opt.threads <= 0 {
        opt.threads = 2;
    }

    let cipher: AESCBC = Cryptgraphy::new(&opt);

    match opt.action.as_str() {
        "encrypt" => cipher.encrypt()?,
        "decrypt" => cipher.decrypt()?,
        _ => return Err(SfError::new(format!("Not defined action: {}", opt.action)))
    }

    Ok(())
}
