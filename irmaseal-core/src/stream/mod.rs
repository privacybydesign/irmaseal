//! Implementation of the IRMAseal stream format. Includes zero-allocation streaming encryption and decryption.

mod opener;
mod sealer;
pub(crate) mod util;

#[cfg(test)]
mod tests;

pub use futures::prelude::*;
pub use opener::*;
pub use sealer::*;

use crate::metadata::{IVSIZE, KEYSIZE};
use ctr::stream_cipher::{NewStreamCipher, StreamCipher};

pub(crate) type Aes = ctr::Ctr128<aes::Aes256>;
pub(crate) type Verifier = hmac::Hmac<sha3::Sha3_256>;

pub struct SymCrypt {
    aes: Aes,
}

/// The tag 'IRMASEAL' with which all IRMAseal bytestreams start.
pub(crate) const PRELUDE: [u8; 4] = [0x14, 0x8A, 0x8E, 0xA7];

/// The stack buffer size that `opener` and `sealer` will use to yield chunks of plaintext and ciphertext.
pub const BLOCKSIZE: usize = 512;
pub const MAX_METADATA_SIZE: usize = 8192;

impl SymCrypt {
    pub async fn new(key: &[u8; KEYSIZE], nonce: &[u8; IVSIZE]) -> Self {
        let aes = Aes::new(key.into(), nonce.into());
        SymCrypt { aes }
    }

    pub async fn encrypt(&mut self, data: &mut [u8]) {
        self.aes.encrypt(data)
    }

    pub async fn decrypt(&mut self, data: &mut [u8]) {
        self.aes.decrypt(data)
    }
}
