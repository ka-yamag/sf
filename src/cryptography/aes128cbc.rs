use std::path::PathBuf;
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

const SALT_SIZE: usize = 32;
const KEY_LENGTH: usize = 32;
const IV_LENGTH: usize = 16;

use super::cryptography;
use cryptography::Cryptgraphy;
use crate::error::SfResult;

pub struct AESCBC<'a> {
    pass: &'a str,
    input: &'a PathBuf,
    output: &'a PathBuf,
    threads: i32,
}

impl<'a> Cryptgraphy<'a> for AESCBC<'a> {
    fn new(pass: &'a str, input: &'a PathBuf, output: &'a PathBuf, threads: i32) -> AESCBC<'a> {
        AESCBC {
            pass: pass,
            input: input,
            output: output,
            threads: threads,
        }
    }

    fn encrypt(&self) -> SfResult {
        // let file_list = cryptography::get_file_list(self.input, self.output, ".mp4").expect("failed to get file list");

        // if file_list.len() == 0 {
        //     println!("non target file");
        //     return Ok(())
        // }

        let rng = rand::SystemRandom::new();

        let mut salt = [0u8; SALT_SIZE];
        rng.fill(&mut salt).unwrap();

        let params = ScryptParams::new(15, 8, 1);
        let mut key = [0u8; KEY_LENGTH];

        scrypt(self.pass.as_bytes(), &salt, &params, &mut key);

        let mut iv = [0u8; IV_LENGTH];
        rng.fill(&mut iv).unwrap();

        // TODO: create file path
        let mut reader = BufReader::new(File::open("/home/zivxyz/code/rust/sf/example.txt")?);
        let mut buf: Vec<u8> = Vec::new();
        reader.read_to_end(&mut buf)?;

        let key_array: &GenericArray<u8, U32> = GenericArray::from_slice(&key);
        let cipher = Cbc::<Aes256, Pkcs7>::new_from_slices(key_array, &iv).unwrap();
        let ciphertext = cipher.encrypt_vec(buf.as_slice());

        let mut msg = Vec::with_capacity(iv.len() + salt.len() + ciphertext.len());
        msg.extend_from_slice(&iv);
        msg.extend_from_slice(&salt);
        msg.extend_from_slice(&ciphertext);

        // TODO: create file path with .sfcvypted
        let mut writer = BufWriter::new(File::create("/home/zivxyz/code/rust/sf/example.txt.sfcrypted")?);
        writer.write_all(msg.as_slice())?;

        Ok(())
    }

    fn decrypt(&self) -> SfResult {
        // TODO: create file path
        let mut reader = BufReader::new(File::open("/home/zivxyz/code/rust/sf/example.txt.sfcrypted")?);
        let mut buf: Vec<u8> = Vec::new();
        reader.read_to_end(&mut buf)?;

        let iv = &buf[0 .. IV_LENGTH];
        let salt = &buf[IV_LENGTH .. IV_LENGTH+SALT_SIZE];
        let ciphertext = &buf[IV_LENGTH+SALT_SIZE ..];

        let params = ScryptParams::new(15, 8, 1);
        let mut key = [0u8; KEY_LENGTH];

        scrypt(self.pass.as_bytes(), &salt, &params, &mut key);
        let key_array: &GenericArray<u8, U32> = GenericArray::from_slice(&key);
        let cipher = Cbc::<Aes256, Pkcs7>::new_from_slices(key_array, &iv).unwrap();

        let plaintext = cipher.decrypt_vec(ciphertext).unwrap();

        // TODO: create file path
        let mut writer = BufWriter::new(File::create("/home/zivxyz/code/rust/sf/example.txt")?);
        writer.write_all(plaintext.as_slice())?;

        Ok(())
    }
}
