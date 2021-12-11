use crate::Opt;
use crate::util::get_file_list_with_type;

use std::io::{BufReader, BufWriter, Read, Write};
use std::fs::File;
use std::sync::{Mutex, Arc};
use std::{panic, thread};
use crypto::scrypt::{scrypt, ScryptParams};
use ring::rand;
use ring::rand::SecureRandom;
use aes::Aes256;
use block_modes::{Cbc, BlockMode, block_padding::Pkcs7};
use crate::error::{SfError, SfResult};
use console::style;
use indicatif::ProgressBar;

pub trait Cryptgraphy<'a> {
    fn new(opt: &'a Opt) -> Self;
    fn encrypt(&self) -> SfResult;
    fn decrypt(&self) -> SfResult;
}

pub struct AESCBC<'a> {
    opt: &'a Opt,
}

pub const SALT_SIZE: usize = 32;
pub const IV_LENGTH: usize = 16;
const KEY_LENGTH: usize = 32;

const SCRYPT_LOGN: u8 = 15;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

const PLAINTEXT_BLOCK_BYTE: usize = 4096;

/*
 * ciphertext.length = (n / blocksize + 1) * blocksize
 *                   = (4096 / 16 + 1) * 16
 *                   = 4112
 */
const CIPHERTEXT_BLOCK_BYTE: usize = 4112;

impl<'a> Cryptgraphy<'a> for AESCBC<'a> {
    fn new(opt: &'a Opt) -> Self {
        AESCBC {
            opt: opt,
        }
    }

    fn encrypt(&self) -> SfResult {
        println!(
            "{} {}",
            style("[+]").bold().cyan(),
            style("Loading files...").bold().green(),
        );

        let file_list = match &self.opt.target_file_format {
            Some(f) => get_file_list_with_type(&self.opt.input, &f)?,
            None => return Err(SfError::new("target_file_format is not set".to_string())),
        };

        if file_list.len() == 0 {
            return Err(SfError::new(format!("Non target file in {}", self.opt.input.display())));
        }

        let pb = Arc::new(Mutex::new(ProgressBar::new(file_list.len() as u64)));
        let mfile_list = Arc::new(Mutex::new(file_list));

        println!(
            "{} {}",
            style("[+]").bold().cyan(),
            style("Generate encryption key...").bold().green(),
        );

        let handles = (0..self.opt.thread.unwrap_or(1)).map(|_| {
            let into_file_list = Arc::clone(&mfile_list);
            let input_dir = self.opt.input.clone();
            let output_dir = self.opt.output.clone();
            let pb = Arc::clone(&pb);
            let password = self.opt.pass.clone();

            // TODO: error handling
            thread::spawn(move || -> SfResult {
                loop {
                    let mut list = into_file_list.lock().unwrap();
                    if list.len() == 0 {
                        return Ok(());
                    }

                    if let Some(target_file) = list.pop() {
                        drop(list);

                        let input_file_name = format!("{}/{}", input_dir.display(), target_file);
                        let output_file_name = format!("{}/{}.sfcrypted", output_dir.display(), target_file);

                        let mut reader = BufReader::new(File::open(&input_file_name)?);
                        let mut writer = BufWriter::new(File::create(output_file_name)?);

                        let rng = rand::SystemRandom::new();

                        let mut iv = [0u8; IV_LENGTH];
                        rng.fill(&mut iv).expect("couldn't get iv randomly");

                        let mut salt = [0u8; SALT_SIZE];
                        rng.fill(&mut salt).expect("couldn't get salt randomly");

                        let params = ScryptParams::new(SCRYPT_LOGN, SCRYPT_R, SCRYPT_P);
                        let mut key = [0u8; KEY_LENGTH];

                        scrypt(password.as_bytes(), &salt, &params, &mut key);

                        let cipher = Cbc::<Aes256, Pkcs7>::new_from_slices(&key, &iv)?;

                        let mut msg = Vec::with_capacity(iv.len() + salt.len());
                        msg.extend_from_slice(&iv);
                        msg.extend_from_slice(&salt);
                        writer.write_all(msg.as_slice())?;
                        writer.flush()?;

                        let mut plaintext = [0; PLAINTEXT_BLOCK_BYTE];

                        while let Ok(()) = reader.read_exact(&mut plaintext) {
                            let ciphertext = cipher.clone().encrypt_vec(&plaintext);

                            writer.write_all(ciphertext.as_slice())?;
                            writer.flush()?;
                        }

                        std::fs::remove_file(input_file_name)?;

                        pb.lock().unwrap().inc(1);
                    }
                }
            })
        })
        .collect::<Vec<_>>();

        println!(
            "{} {}",
            style("[+]").bold().cyan(),
            style("Start encrypting files...").bold().green(),
        );

        for h in handles {
            match h.join() {
                Ok(_) => {},
                Err(e) => panic::resume_unwind(e),
            }
        }

        pb.lock().unwrap().finish();

        println!(
            "{} {}",
            style("[+]").bold().cyan(),
            style("finish").bold().green(),
        );

        Ok(())
    }

    fn decrypt(&self) -> SfResult {
        println!(
            "{} {}",
            style("[+]").bold().cyan(),
            style("Loading files...").bold().green(),
        );

        let file_list = get_file_list_with_type(&self.opt.input, "sfcrypted")?;
        if file_list.len() == 0 {
            return Err(SfError::new(format!("Non target file in {}", self.opt.input.display())));
        }

        let pb = Arc::new(Mutex::new(ProgressBar::new(file_list.len() as u64)));
        let file_list = Arc::new(Mutex::new(file_list));

        let handles = (0..self.opt.thread.unwrap_or(1)).map(|_| {
            let input_dir = self.opt.input.clone();
            let output_dir = self.opt.output.clone();
            let password = self.opt.pass.clone();
            let file_list = Arc::clone(&file_list);
            let pb = Arc::clone(&pb);

            thread::spawn(move || -> SfResult {
                loop {
                    let mut list = file_list.lock().unwrap();
                    if list.len() == 0 {
                        return Ok(());
                    }

                    if let Some(target_file) = list.pop() {
                        drop(list);

                        let input_file_name = format!("{}/{}", input_dir.display(), target_file);
                        let output_file_name = format!("{}/{}", output_dir.display(), target_file.trim_end_matches(".sfcrypted"));

                        let mut reader = BufReader::new(File::open(&input_file_name)?);
                        let mut writer = BufWriter::new(File::create(output_file_name)?);

                        let mut iv = [0; IV_LENGTH];
                        reader.read_exact(&mut iv)?;

                        let mut salt = [0; SALT_SIZE];
                        reader.read_exact(&mut salt)?;

                        let params = ScryptParams::new(SCRYPT_LOGN, SCRYPT_R, SCRYPT_P);
                        let mut key = [0u8; KEY_LENGTH];
                        scrypt(password.as_bytes(), &salt, &params, &mut key);

                        let cipher = Cbc::<Aes256, Pkcs7>::new_from_slices(&key, &iv).unwrap();

                        let mut ciphertext = [0; CIPHERTEXT_BLOCK_BYTE];

                        while let Ok(()) = reader.read_exact(&mut ciphertext) {
                            let plaintext = cipher.clone().decrypt_vec(&ciphertext).expect("failed to decrypt error");
                            writer.write_all(plaintext.as_slice())?;
                            writer.flush()?;
                        }

                        std::fs::remove_file(input_file_name)?;

                        pb.lock().unwrap().inc(1);
                    }
                }
            })
        })
        .collect::<Vec<_>>();

        println!(
            "{} {}",
            style("[+]").bold().cyan(),
            style("Start decrypting files...").bold().green(),
        );

        for h in handles {
            match h.join() {
                Ok(_) => {},
                Err(e) => panic::resume_unwind(e),
            }
        }

        pb.lock().unwrap().finish();

        println!(
            "{} {}",
            style("[+]").bold().cyan(),
            style("finish").bold().green(),
        );

        Ok(())
    }
}
