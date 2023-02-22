use crate::error::SfError;
use std::path::PathBuf;

pub struct Files {
    target_file_format: String,
    input_dir: PathBuf,
}

impl Files {
    fn new(file_format: &str, input_dir: PathBuf) -> Self {
        Files {
            target_file_format: file_format.to_string(),
            input_dir: input_dir,
        }
    }

    fn get_file_list(&self) -> Result<Vec<std::string::String>, SfError> {
        let list = std::fs::read_dir(&self.input_dir)?
            .filter_map(Result::ok)
            .filter(|f| f.path().is_file())
            .filter(|f| {
                f.path()
                    .extension()
                    .expect("failed to get file type")
                    .to_str()
                    .expect("failed to convert to str")
                    .contains(&self.target_file_format)
            })
            .map(|f| {
                f.file_name()
                    .to_str()
                    .expect("failed to convert to str")
                    .to_string()
            })
            .collect::<Vec<_>>();
        Ok(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    // TODO: test name
    #[test]
    fn test_get_file_list_with_type_for_mp4_files() -> Result<(), SfError> {
        let dir = tempdir()?;

        let tmp_file_list = vec![
            "0057a2b4-fb8c-46bb-8133-ef9920b7bced.mp4",
            "c7dc8644-8559-44f5-96e8-ecc035067856.mp4",
            "0057a2b4-fb8c-46bb-8133-ef9920b7bced.enc",
            "52f49ff1-3874-4c93-91f4-3c3c78d159fd.enc",
            "test.txt",
            "recording.mp4",
            "test.mp4.sfcrypted",
        ];

        for f in &tmp_file_list {
            fs::File::create(dir.path().join(f))?;
        }
        let tmp_dir_path = &dir.into_path();

        let f = Files::new("mp4", tmp_dir_path.to_path_buf());
        let mut actual = f.get_file_list()?;

        let mut expect = vec![
            "0057a2b4-fb8c-46bb-8133-ef9920b7bced.mp4",
            "c7dc8644-8559-44f5-96e8-ecc035067856.mp4",
            "recording.mp4",
        ];

        assert_eq!(actual.len(), expect.len());

        actual.sort();
        expect.sort();
        assert_eq!(actual, expect);

        fs::remove_dir_all(tmp_dir_path)?;

        Ok(())
    }

    #[test]
    fn test_get_file_list_with_type_for_sfcrypted_files() -> Result<(), SfError> {
        let dir = tempdir()?;

        let tmp_file_list = vec![
            "0057a2b4-fb8c-46bb-8133-ef9920b7bced.mp4.sfcrypted",
            "c7dc8644-8559-44f5-96e8-ecc035067856.mp4",
            "0057a2b4-fb8c-46bb-8133-ef9920b7bced.sfcrypted",
            "52f49ff1-3874-4c93-91f4-3c3c78d159fd.enc",
            "test.txt.sfcrypted",
            "recording.mp4",
            "test.mp4.sfcrypted",
        ];

        for f in &tmp_file_list {
            fs::File::create(dir.path().join(f))?;
        }
        let tmp_dir_path = &dir.into_path();

        let mut expect = vec![
            "0057a2b4-fb8c-46bb-8133-ef9920b7bced.mp4.sfcrypted",
            "0057a2b4-fb8c-46bb-8133-ef9920b7bced.sfcrypted",
            "test.txt.sfcrypted",
            "test.mp4.sfcrypted",
        ];

        let f = Files::new("sfcrypted", tmp_dir_path.to_path_buf());
        let mut actual = f.get_file_list()?;

        assert_eq!(actual.len(), expect.len());

        actual.sort();
        expect.sort();
        assert_eq!(actual, expect);

        fs::remove_dir_all(tmp_dir_path)?;

        Ok(())
    }
}
