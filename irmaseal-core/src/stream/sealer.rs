use core::convert::TryFrom;
use hmac::Mac;
use postcard::to_slice;
use rand::{CryptoRng, Rng};
use std::vec::Vec;

use crate::stream::*;
use crate::Error::{ReadError, WriteError};
use crate::*;
use futures::executor::block_on;
use futures::io::AllowStdIo;
use futures::{AsyncReadExt, AsyncWriteExt};

/// Sealer for an bytestream, which converts it into an IRMAseal encrypted bytestream.
pub struct Sealer<'a, W: AsyncWrite + Unpin> {
    aes: SymCrypt,
    hmac: Verifier,
    output_writer: W,
}

// TODO: What to do with Writable?
impl<'a, W: AsyncWrite + Unpin> Sealer<'a, W> {
    pub async fn new<R: Rng + CryptoRng>(
        i: &Identity,
        pk: &PublicKey,
        rng: &mut R,
        mut w: W,
    ) -> Result<Self, Error> {
        let derived = i.derive()?;
        let (c, k) = ibe::kiltz_vahlis_one::encrypt(&pk.0, &derived, rng);

        let (aeskey, mackey) = crate::stream::util::derive_keys(&k);
        let iv = crate::stream::util::generate_iv(rng);

        let aes = SymCrypt::new(&aeskey.into(), &iv.into());
        let mut hmac = Verifier::new_varkey(&mackey).unwrap();

        let metadata = Metadata::new(Version::V1_0, &ciphertext, &iv, i)?;
        let mut deser_buf = [0; MAX_METADATA_SIZE];
        let meta_bytes = to_slice(&metadata, &mut deser_buf).or(Err(Error::FormatViolation))?;

        let metadata_len = u16::try_from(meta_bytes.len())
            .or(Err(Error::FormatViolation))?
            .to_be_bytes();

        hmac.write(&PRELUDE)?;
        w.write_all(&PRELUDE).map_err(|e| WriteError(e)).await?;

        hmac.write(&metadata_len)?;
        w.write(&metadata_len).map_err(|e| WriteError(e)).await?;

        hmac.write(&meta_bytes)?;
        w.write(meta_bytes).map_err(|e| WriteError(e)).await?;

        if metadata_len.len() > MAX_METADATA_SIZE {
            Err(Error::FormatViolation)
        } else {
            Ok(Sealer {
                aes,
                hmac,
                output_writer: w,
            })
        }
    }

    pub async fn seal<R: AsyncRead + Unpin>(&mut self, mut r: R) -> Result<(), Error> {
        let mut tmp = [0u8; BLOCKSIZE];

        loop {
            let input_length = r.read(&mut tmp).map_err(|err| ReadError(err)).await?;
            if input_length == 0 {
                break;
            }
            let data = &mut buffer[..input_length];
            self.aes.encrypt(data).await;
            self.hmac.input(data);
            self.output_writer
                .write_all(data)
                .map_err(|err| WriteError(err))
                .await?;
        }

        Ok(())
    }
}

impl Writable for Verifier {
    fn write(&mut self, buf: &[u8]) -> Result<(), LegacyError> {
        self.input(buf);
        Ok(())
    }
}

impl<'a, W: AsyncWrite + Unpin> Drop for Sealer<'a, W> {
    fn drop(&mut self) {
        let code = self.hmac.result_reset().code();
        block_on(|_| self.output_writer.write_all(&code).unwrap())
    }
}
