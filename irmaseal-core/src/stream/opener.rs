use crate::stream::*;
use crate::*;

use arrayref::array_ref;
use arrayvec::ArrayVec;
use core::convert::TryInto;
use ctr::stream_cipher::{NewStreamCipher, StreamCipher};
use hmac::Mac;

/// Opener of an IRMAseal encrypted bytestream.
/// It reads the IRMAseal header, and yields the recipient Identity for which the content is intended.
///
/// Enables the library user to lookup the UserSecretKey corresponding to this Identity before continuing.
pub struct OpenerSealed<R: AsyncRead + Unpin> {
    input_reader: R, // TODO: What to do with Readable
    metadata_buf: ArrayVec<[u8; MAX_METADATA_SIZE]>,
}

impl<R: AsyncRead + Unpin> OpenerSealed<R> {
    /// Starts interpreting a bytestream as an IRMAseal stream.
    /// Will immediately detect whether the bytestream actually is such a stream, and will yield
    /// the identity for which the stream is intended, as well as the stream continuation.
    pub async fn new(mut r: R) -> Result<(Metadata, Self), Error> {
        let mut buffer = [0u8; 14];
        r.read_exact(&mut buffer)
            .map_err(|err| Error::ReadError(err))
            .await?;
        if buffer[..4] != PRELUDE {
            return Err(Error::NotIRMASEAL);
        }

        let meta_len = usize::from(u16::from_be_bytes(
            ar.read_bytes_strict(core::mem::size_of::<u16>())?
                .try_into()
                .unwrap(),
        ));
        if meta_len > MAX_METADATA_SIZE {
            return Err(Error::FormatViolation);
        }

        let mut metadata_buf: ArrayVec<[u8; MAX_METADATA_SIZE]> = ArrayVec::new();
        unsafe {
            // Above we check whether the meta_len exceeds the MAX_METADATA_SIZE, so
            // the length assertion that makes this call unsafe cannot happen.
            metadata_buf.set_len(meta_len);
        }
        r.read_exact(metadata_buf.as_mut_slice())
            .map_err(|err| Error::ReadError(err))
            .await?;

        let metadata =
            postcard::from_bytes(&metadata_buf[..meta_len]).or(Err(Error::FormatViolation))?;

        Ok((
            metadata,
            OpenerSealed {
                input_reader: r,
                metadata_buf,
            },
        ))
    }

    /// Will unseal the stream continuation and write the plaintext in the given writer.
    pub async fn unseal<W: AsyncWrite + Unpin>(
        mut self,
        usk: &UserSecretKey,
        mut output: W,
    ) -> Result<bool, Error> {
        let mut ciphertext_buffer = [0u8; 144];
        self.input_reader
            .read_exact(&mut ciphertext_buffer)
            .map_err(|err| Error::ReadError(err))
            .await?;
        let c = crate::util::open_ct(ibe::kiltz_vahlis_one::CipherText::from_bytes(
            &ciphertext_buffer,
        ))
        .ok_or(Error::FormatViolation)?;

        let m = ibe::kiltz_vahlis_one::decrypt(&usk.0, &c);
        let (skey, mackey) = crate::stream::util::derive_keys(&m);

        let mut hmac = Verifier::new_varkey(&mackey).unwrap();

        let iv: &[u8; IVSIZE] = array_ref!(metadata.iv.as_slice(), 0, IVSIZE);

        hmac.input(self.metadata.as_slice());

        let mut aes = SymCrypt::new(&skey.into(), &iv).await;
        let mut buffer_vec = [u8; BLOCKSIZE + MACSIZE]; // TODO: size?
        let buffer = buffer_vec.as_mut_slice();

        // The input buffer must at least contain enough bytes for a MAC to be included.
        self.input_reader
            .read_exact(&mut buffer[..MACSIZE])
            .map_err(|err| Error::ReadError(err))
            .await?;

        let mut buffer_tail = MACSIZE;
        loop {
            let input_length = self
                .input_reader
                .read(&mut buffer[buffer_tail..])
                .map_err(|err| Error::ReadError(err))
                .await?;
            buffer_tail += input_length;

            // Start encrypting when we have read enough data to put aside a new MAC
            // or when we have hit EOF when reading and we still have data left to encrypt.
            if buffer_tail >= 2 * MACSIZE || input_length == 0 && buffer_tail > MACSIZE {
                let mut block = &mut buffer[0..buffer_tail - MACSIZE];
                hmac.input(&mut block);
                aes.encrypt(&mut block).await;
                output
                    .write_all(&mut block)
                    .map_err(|err| Error::WriteError(err))
                    .await?;

                // Make sure potential MAC is shifted to the front of the array.
                let mut tmp = [0u8; MACSIZE];
                tmp.copy_from_slice(&buffer[buffer_tail - MACSIZE..buffer_tail]);
                buffer[..MACSIZE].copy_from_slice(&tmp);

                buffer_tail = MACSIZE;
            }

            if input_length == 0 {
                break;
            }
        }
        Ok(hmac.verify(&buffer[..MACSIZE]).is_ok())
    }
}
