use std::path::PathBuf;
use std::fs;
use crate::error::{SfError, SfResult};
use crate::Opt;
use aes::cipher::{
    generic_array::{GenericArray, typenum::U32},
};
use super::aes128cbc::{IV_LENGTH, SALT_SIZE};

pub fn get_file_list(input_dir: &PathBuf) -> Result<Vec<std::string::String>, SfError> {
    let list = fs::read_dir(input_dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        // .filter(|e| e.display().to_string().contains(file_type))
        .map(|f| f.file_name().expect("failed to get filename")
            .to_str().expect("failed to convert to str")
            // .split(".")
            // .collect::<Vec<&str>>()[0]
            .to_string())
        .collect::<Vec<_>>();

    // let check_file_type = match file_type {
    //     ".sfcrypted" => ".mp4",
    //     ".mp4" => ".sfcrypted",
    //     _ => return Err(SfError::new("invalid file_type for file list".to_owned()))
    // };

    // for (i, f) in list.clone().iter().enumerate() {
        // if Path::new(&format!("{}/{}{}", output_dir.display(), f, check_file_type)).exists() {
        //     list.remove(i);
        // }
    // }

    Ok(list)
}

// TODO:
fn remove_deplicate_files(list: Vec<std::string::String>, file_type: &str) {
}

pub fn get_file_list_with_type(input_dir: &PathBuf, file_type: &str) -> Result<Vec<std::string::String>, SfError> {
    let list = fs::read_dir(input_dir)?
        .filter_map(Result::ok)
        .filter(|f| f.path().is_file())
        .filter(|f| f.path().extension().expect("failed to get file type")
                .to_str().expect("failed to convert to str").contains(file_type))
        .map(|f| f.file_name()
             .to_str().expect("failed to convert to str").to_string())
        .collect::<Vec<_>>();

    Ok(list)
}

pub trait Cryptgraphy<'a> {
    // fn new(key: &'a str, input: &'a PathBuf, output: &'a PathBuf, threads: i32) -> Self;
    fn new(opt: &'a Opt) -> Self;
    fn generate_key(&self) -> Result<(GenericArray<u8, U32>, [u8; IV_LENGTH], [u8; SALT_SIZE]), SfError>;
    fn encrypt(&self) -> SfResult;
    fn decrypt(&self) -> SfResult;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::tempdir;

    #[test]
    fn test_get_file_list_with_type() -> Result<(), SfError> {
        let dir = tempdir()?;

        let tmp_file_list = vec![
            "0057a2b4-fb8c-46bb-8133-ef9920b7bced.mp4",
            "c7dc8644-8559-44f5-96e8-ecc035067856.mp4",
            "0057a2b4-fb8c-46bb-8133-ef9920b7bced.enc",
            "52f49ff1-3874-4c93-91f4-3c3c78d159fd.enc",
            "test.txt",
            "recording.mp4",
        ];
        
        for f in &tmp_file_list {
            File::create(dir.path().join(f))?;
        }
        let tmp_dir_path = &dir.into_path();

        let mut expect = vec![
            "0057a2b4-fb8c-46bb-8133-ef9920b7bced.mp4",
            "c7dc8644-8559-44f5-96e8-ecc035067856.mp4",
            "recording.mp4",
        ];
        
        let mut actual = get_file_list_with_type(&tmp_dir_path, "mp4")?;

        assert_eq!(actual.len(), expect.len());

        actual.sort();
        expect.sort();
        assert_eq!(actual, expect);

        fs::remove_dir_all(tmp_dir_path)?;

        Ok(())
    }
}
