use std::path::{PathBuf, Path};
use crate::error::{SfError, SfResult};

pub fn get_file_list(input_dir: &PathBuf, output_dir: &PathBuf, file_type: &str) -> Result<Vec<std::string::String>, SfError> {
    let mut list = std::fs::read_dir(input_dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|e| e.display().to_string().contains(file_type))
        .map(|f| f.file_name().expect("failed to get filename")
            .to_str().expect("failed to convert to str")
            .split(".")
            .collect::<Vec<&str>>()[0]
            .to_string())
        .collect::<Vec<_>>();

    let check_file_type = match file_type {
        ".enc" => ".mp4",
        ".mp4" => ".enc",
        _ => return Err(SfError::new("invalid file_type for file list".to_owned()))
    };

    for (i, f) in list.clone().iter().enumerate() {
        if Path::new(&format!("{}/{}{}", output_dir.display(), f, check_file_type)).exists() {
            list.remove(i);
        }
    }

    Ok(list)
}

pub trait Cryptgraphy<'a> {
    fn new(key: &'a str, input: &'a PathBuf, output: &'a PathBuf, threads: i32) -> Self;
    fn encrypt(&self) -> SfResult;
    fn decrypt(&self) -> SfResult;
}
