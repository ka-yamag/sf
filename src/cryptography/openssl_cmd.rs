// use std::path::{PathBuf, Path};
// use std::process::Command;
// use std::io::{self, Write};
// use std::thread;
// use std::sync::{Mutex, Arc};

// use uuid::Uuid;
// use pbr::ProgressBar;
// use regex::Regex;

// use super::cryptography;
// use cryptography::Cryptgraphy;
// use crate::error::SfResult;

// pub struct OpenSSLAesCommand<'a> {
//     opt: &'a Opt,
// }

// impl<'a> Cryptgraphy<'a> for OpenSSLAesCommand<'a> {
//     // fn new(key: &'a str, input: &'a PathBuf, output: &'a PathBuf, threads: i32) -> OpenSSLAesCommand<'a> {
//     fn new(opt: &Opt) -> OpenSSLAesCommand {
//         OpenSSLAesCommand {
//             opt: opt,
//         }
//     }

//     fn encrypt(&self) -> SfResult {
//         let file_list = cryptography::get_file_list(self.opt.input, ".mp4").expect("failed to get file list");

//         if file_list.len() == 0 {
//             println!("non target file");
//             return Ok(())
//         }

//         let mut pb = Arc::new(Mutex::new(ProgressBar::new(file_list.len() as u64)));
//         let mfile_list = Arc::new(Mutex::new(file_list));

//         let mut thread_handlers = vec![];

//         for _ in 0..self.opt.threads {
//             let file_list = Arc::clone(&mfile_list);
//             let tpb = Arc::clone(&mut pb);

//             let input_dir = self.opt.input.clone();
//             let output_dir = self.opt.output.clone();
//             let key = self.opt.key.to_owned();

//             thread_handlers.push(thread::spawn(move || -> SfResult {
//                 loop {
//                     if let Ok(mut list) = file_list.lock() {
//                         if list.len() == 0 {
//                             return Ok(())
//                         }

//                         if let Some(target_file) = list.pop() {
//                             drop(list);

//                             let re = Regex::new(
//                                 r"[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}")?;

//                             let mut output_filename = String::new();

//                             if re.is_match(&target_file) {
//                                 output_filename = target_file.clone();
//                             } else {
//                                 loop {
//                                     let uuid = Uuid::new_v4();
//                                     output_filename = uuid.to_hyphenated().to_string();
//                                     if !Path::new(&output_filename).exists() {
//                                         break
//                                     }
//                                 }
//                             }

//                             let cmd_result = Command::new("openssl")
//                                 .args(&[
//                                       "aes-256-cbc",
//                                       "-a",
//                                       "-salt",
//                                       "-pbkdf2",
//                                       "-in",
//                                       &format!("{}/{}.mp4", input_dir.display(), target_file),
//                                       "-out",
//                                       &format!("{}/{}.enc", output_dir.display(), output_filename),
//                                       "-k",
//                                       &key,
//                                 ])
//                                 .output()?;

//                             if cmd_result.status.success() {
//                                 tpb.lock().expect("failed to get progress bar").inc();
//                                 tpb.lock().expect("failed to get progress bar").tick();
//                             } else {
//                                 // TODO: collect error
//                                 println!("failed to encrypt {}/{}", input_dir.display(), target_file);
//                                 io::stderr().write_all(&cmd_result.stderr)?;
//                                 println!("");
//                             }
//                         }
//                     }
//                 }
//             }));
//         }

//         for handler in thread_handlers {
//             // TODO
//             handler.join().unwrap()?;
//         }

//         pb.lock().expect("failed to get progress bar").finish_println("done");

//         Ok(())
//     }

//     fn decrypt(&self) -> SfResult {
//         let file_list = cryptography::get_file_list(self.opt.input, self.opt.output, ".enc").expect("failed to get file list");

//         if file_list.len() == 0 {
//             println!("non target file");
//             return Ok(())
//         }

//         let mut pb = Arc::new(Mutex::new(ProgressBar::new(file_list.len() as u64)));
//         let mfile_list = Arc::new(Mutex::new(file_list));
//         let mut thread_handlers = vec![];

//         for _ in 0..self.opt.threads {
//             let file_list = Arc::clone(&mfile_list);
//             let tpb = Arc::clone(&mut pb);

//             let input_dir = self.opt.input.clone();
//             let output_dir = self.opt.output.clone();
//             let key = self.opt.key.to_owned();

//             thread_handlers.push(thread::spawn(move || -> SfResult {
//                 loop {
//                     if let Ok(mut list) = file_list.lock() {
//                         if list.len() == 0 {
//                             return Ok(())
//                         }

//                         if let Some(target_file) = list.pop() {
//                             drop(list);

//                             let cmd_result = Command::new("openssl")
//                                 .args(&[
//                                       "aes-256-cbc",
//                                       "-d",
//                                       "-a",
//                                       "-pbkdf2",
//                                       "-in",
//                                       &format!("{}/{}.enc", input_dir.display(), target_file),
//                                       "-out",
//                                       &format!("{}/{}.mp4", output_dir.display(), target_file),
//                                       "-k",
//                                       &key,
//                                 ])
//                                 .output()?;

//                             if cmd_result.status.success() {
//                                 tpb.lock().expect("failed to get progress bar").inc();
//                                 tpb.lock().expect("failed to get progress bar").tick();
//                             } else {
//                                 // TODO: collect error
//                                 println!("failed to encrypt {}/{}.enc", input_dir.display(), target_file);
//                                 io::stderr().write_all(&cmd_result.stderr)?;
//                                 println!("");
//                             }
//                         }
//                     }
//                 }
//             }));
//         }

//         for handler in thread_handlers {
//             // TODO
//             handler.join().unwrap()?;
//         }

//         Ok(())
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use std::fs;
//     use std::fs::File;
//     use tempfile::tempdir;

//     #[test]
//     fn test_get_file_list_when_encrypt() {
//         let dir = tempdir().unwrap();

//         let tmp_file_list = vec![
//             "0057a2b4-fb8c-46bb-8133-ef9920b7bced.mp4",
//             "c7dc8644-8559-44f5-96e8-ecc035067856.mp4",
//             "0057a2b4-fb8c-46bb-8133-ef9920b7bced.enc"
//         ];

//         for f in &tmp_file_list {
//             File::create(dir.path().join(f)).unwrap();
//         }

//         let as_pathbuf = &dir.into_path();

//         let file_list = get_file_list(&as_pathbuf, &as_pathbuf, ".mp4").expect("fail");

//         assert_eq!(file_list.len(), 1);

//         fs::remove_dir_all(as_pathbuf).unwrap();
//     }

//     #[test]
//     fn test_get_file_list_when_decrypt() {
//         let dir = tempdir().unwrap();

//         let tmp_file_list = vec![
//             "0057a2b4-fb8c-46bb-8133-ef9920b7bced.enc",
//             "c7dc8644-8559-44f5-96e8-ecc035067856.enc",
//             "0057a2b4-fb8c-46bb-8133-ef9920b7bced.mp4"
//         ];

//         for f in &tmp_file_list {
//             File::create(dir.path().join(f)).unwrap();
//         }

//         let as_pathbuf = &dir.into_path();

//         let file_list = get_file_list(&as_pathbuf, &as_pathbuf, ".enc").expect("fail");

//         assert_eq!(file_list.len(), 1);

//         fs::remove_dir_all(as_pathbuf).unwrap();
//     }
// }
