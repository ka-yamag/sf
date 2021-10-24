use std::io::{BufReader, BufWriter, Read, Write};
use std::fs::File;
use crypto::scrypt::{scrypt, ScryptParams};
use ring::rand;
use ring::rand::SecureRandom;
use aes::Aes256;
use aes::cipher::{
    generic_array::{GenericArray, typenum::U32},
};
use block_modes::{Cbc, BlockMode, block_padding::Pkcs7};
use crate::Opt;

use crate::cryptography::cryptography::{
    Cryptgraphy
};
// use super::cryptography::{self, get_file_list, get_file_list_with_type};
use crate::error::{SfError, SfResult};

pub struct AESCBC<'a> {
    opt: &'a Opt,
}

pub const SALT_SIZE:  usize = 32;
pub const IV_LENGTH:  usize = 16;
const KEY_LENGTH: usize = 32;

const SCRYPT_LOGN: u8 = 15;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

const TMP_INPUT_FILE: &str = "/home/zivxyz/code/rust/sf/hoge.mp4";
const TMP_FILE: &str = "/home/zivxyz/code/rust/sf/hoge2.mp4";
const TMP_OUTPUT_FILE: &str = "/home/zivxyz/code/rust/sf/hoge.mp4.sfcrypted";

impl<'a> Cryptgraphy<'a> for AESCBC<'a> {
    fn new(opt: &'a Opt) -> Self {
        AESCBC {
            opt: opt,
        }
    }

    fn generate_key(&self) -> Result<(GenericArray<u8, U32>, [u8; IV_LENGTH], [u8; SALT_SIZE]), SfError> {
        let rng = rand::SystemRandom::new();

        let mut iv = [0u8; IV_LENGTH];
        rng.fill(&mut iv).expect("couldn't get iv randomly");

        let mut salt = [0u8; SALT_SIZE];
        rng.fill(&mut salt).expect("couldn't get salt randomly");

        let params = ScryptParams::new(SCRYPT_LOGN, SCRYPT_R, SCRYPT_P);
        let mut key = [0u8; KEY_LENGTH];

        scrypt(self.opt.pass.as_bytes(), &salt, &params, &mut key);

        let key_array: &GenericArray<u8, U32> = GenericArray::from_slice(&key);

        Ok((*key_array, iv, salt))
    }

    fn encrypt(&self) -> SfResult {
        // let file_list = if self.opt.target_file_format == "" {
        //     get_file_list(&self.opt.input)?
        // } else {
        //     get_file_list_with_type(&self.opt.input, &self.opt.target_file_format)?
        // };

        // if file_list.len() == 0 {
        //     println!("non target file");
        //     return Ok(())
        // }

        let (key_array, iv, salt) = self.generate_key()?;

        let cipher = Cbc::<Aes256, Pkcs7>::new_from_slices(&key_array, &iv).unwrap();
        let mut reader = BufReader::new(File::open(TMP_INPUT_FILE)?);
        let mut writer = BufWriter::new(File::create(TMP_OUTPUT_FILE)?);

        let mut msg = Vec::with_capacity(iv.len() + salt.len());
        msg.extend_from_slice(&iv);
        msg.extend_from_slice(&salt);
        writer.write_all(msg.as_slice())?;

        // let mut first_block = BufWriter::new(File::create("first_when_encrypt.bin")?);
        // let mut count = 0;

        let mut buf = [0; 4096];
        loop {
            if let Ok(()) = reader.read_exact(&mut buf) {
                let plaintext = &buf[..];
                let ciphertext = cipher.clone().encrypt_vec(&plaintext);
                writer.write_all(ciphertext.as_slice())?;
                writer.flush()?;
            } else {
                break;
            }

            // match reader.read(&mut buf)? {
            //     0 => break,
            //     n => {
            //         let plaintext = &buf[..];
            //         let ciphertext = cipher.clone().encrypt_vec(&plaintext);
            //         // count += 1;

            //         // // TODO: ここで出てきた暗号文と、復号時で出た平文との比較を行う
            //         // if count == 2 {
            //         //     first_block.write_all(ciphertext.as_slice())?;
            //         //     println!("len: {:?}", ciphertext.len());
            //         // }

            //         writer.write_all(ciphertext.as_slice())?;
            //         writer.flush()?;
            //     }
            // }
        }

        Ok(())
    }

    fn decrypt(&self) -> SfResult {
        let mut reader = BufReader::new(File::open(TMP_OUTPUT_FILE)?);
        let mut writer = BufWriter::new(File::create(TMP_FILE)?);

        let mut iv = [0; IV_LENGTH];
        reader.read_exact(&mut iv)?;

        let mut salt = [0; SALT_SIZE];
        reader.read_exact(&mut salt)?;

        let params = ScryptParams::new(SCRYPT_LOGN, SCRYPT_R, SCRYPT_P);
        let mut key = [0u8; KEY_LENGTH];
        scrypt(self.opt.pass.as_bytes(), &salt, &params, &mut key);
        let key_array: &GenericArray<u8, U32> = GenericArray::from_slice(&key);

        let cipher = Cbc::<Aes256, Pkcs7>::new_from_slices(key_array, &iv).unwrap();

        // ciphertext.length = (n / blocksize + 1) * blocksize
        // = (4096 / 16 + 1) * 16
        // = 4112
        let mut buf = [0; 4112];
        loop {
            if let Ok(()) = reader.read_exact(&mut buf) {
                // println!("round {:?}", count);
                let ciphertext = &buf[..];

                // if count == 2 {
                //     first_block.write_all(ciphertext)?;
                //     println!("len: {:?}", ciphertext.len());
                // }

                let plaintext = cipher.clone().decrypt_vec(&ciphertext).expect("failed to decrypt error");

                writer.write_all(plaintext.as_slice())?;
                writer.flush()?;
            } else {
                break;
            }

            // match reader.read(&mut buf)? {
            //     0 => break,
            //     n => {
            //         // ２回めが短い？
            //         println!("round {:?}; loaded : {:?}", count, n);
            //         let ciphertext = &buf[..];
            //         count += 1;

            //         if count == 2 {
            //             first_block.write_all(ciphertext)?;
            //             println!("len: {:?}", ciphertext.len());
            //         }

            //         let plaintext = cipher.clone().decrypt_vec(&ciphertext).expect("failed to decrypt error");

            //         writer.write_all(plaintext.as_slice())?;
            //         writer.flush()?;
            //     }
            // }
        }

        Ok(())
    }
}
