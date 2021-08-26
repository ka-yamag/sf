mod cryptography;
mod error;

use structopt::StructOpt;
use std::path::PathBuf;

use cryptography::cryptography::Cryptgraphy;
use cryptography::aes128cbc::AESCBC;
use error::{SfResult, SfError};

#[derive(StructOpt)]
struct Opt {
    /// Action
    action: String,

    /// Password
    pass: String,

    /// The number of thread
    threads: i32,

    /// Input dir
    #[structopt(short, long, parse(from_os_str))]
    input: PathBuf,

    /// Output dir
    #[structopt(short, long, parse(from_os_str), required_if("out", "dir"))]
    output: PathBuf,
}

fn main() -> SfResult {
    let opt = Opt::from_args();

    if !opt.input.is_dir() || !opt.output.is_dir() {
        return Err(SfError::new("input or output is not directory".to_string()))
    }

    if opt.pass == "" {
        return Err(SfError::new("key is empty".to_string()))
    }

    let cipher: AESCBC = Cryptgraphy::new(
        &opt.pass,
        &opt.input,
        &opt.output,
        opt.threads,
    );
    match opt.action.as_str() {
        "encrypt" => cipher.encrypt()?,
        "decrypt" => cipher.decrypt()?,
        _ => return Err(SfError::new(format!("Not defined action: {}", opt.action)))
    }

    Ok(())
}
