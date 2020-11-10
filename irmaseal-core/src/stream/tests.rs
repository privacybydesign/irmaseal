use crate::stream::*;
use crate::*;

use arrayvec::ArrayVec;
use core::pin::Pin;
use futures::executor::block_on;
use futures::io::{Error, ErrorKind};
use futures::task::{Context, Poll};
use rand::RngCore;

type BigBuf = ArrayVec<[u8; 65536]>;

struct BigBufWriter<'a> {
    big_buf: &'a mut BigBuf,
}

impl<'a> AsyncWrite for BigBufWriter<'a> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let big_buf = &mut (*self).big_buf;
        if big_buf.remaining_capacity() < buf.len() {
            Poll::Ready(Err(Error::new(
                ErrorKind::UnexpectedEof,
                "size exceeded max BigBuf length",
            )))
        } else {
            big_buf
                .write(buf)
                .map_err(|_| Error::new(ErrorKind::Other, "error while writing to ArrayVec"))?;
            Poll::Ready(Ok(buf.len()))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
}

struct DefaultProps {
    pub i: Identity,
    pub pk: ibe::kiltz_vahlis_one::PublicKey,
    pub sk: ibe::kiltz_vahlis_one::SecretKey,
}

impl Default for DefaultProps {
    fn default() -> DefaultProps {
        let mut rng = rand::thread_rng();
        let i = Identity::new(
            1566722350,
            "pbdf.pbdf.email.email",
            Some("w.geraedts@sarif.nl"),
        )
        .unwrap();

        let (pk, sk) = ibe::kiltz_vahlis_one::setup(&mut rng);

        DefaultProps { i, pk, sk }
    }
}

async fn seal<'a>(props: &DefaultProps, content: &[u8]) -> BigBuf {
    let mut rng = rand::thread_rng();
    let DefaultProps { i, pk, sk: _ } = props;

    let mut big_buf = BigBuf::new();
    let mut buf_writer = BigBufWriter {
        big_buf: &mut big_buf,
    };

    let mut s = Sealer::new(i.clone(), &PublicKey(pk.clone()), &mut rng, &mut buf_writer)
        .await
        .unwrap();
    s.seal(content).await.unwrap();

    big_buf
}

async fn unseal(props: &DefaultProps, buf: &[u8]) -> (BigBuf, bool) {
    let mut rng = rand::thread_rng();
    let DefaultProps { i, pk, sk } = props;

    let (m, o) = OpenerSealed::new(buf).await.unwrap();
    let i2 = &m.identity;

    assert_eq!(&i, &i2);

    let usk = ibe::kiltz_vahlis_one::extract_usk(&pk, &sk, &i2.derive().unwrap(), &mut rng);
    let mut big_buf = BigBuf::new();
    let mut dst = BigBufWriter {
        big_buf: &mut big_buf,
    };
    let validated = o.unseal(&m, &UserSecretKey(usk), &mut dst).await.unwrap();

    println!("Decrypted:\n{:?}", big_buf.as_slice());
    (big_buf, validated)
}

async fn seal_and_unseal(props: &DefaultProps, content: &[u8]) -> (BigBuf, bool) {
    println!("Plain:\n{:?}", content);
    let buf = seal(props, content).await;
    println!("Encrypted:\n{:?}", buf.as_slice());
    unseal(props, &buf).await
}

fn do_test(props: &DefaultProps, content: &mut [u8]) {
    rand::thread_rng().fill_bytes(content);
    let (dst, valid) = block_on(seal_and_unseal(props, content));

    assert_eq!(&content.as_ref(), &dst.as_slice());
    assert!(valid);
}

#[test]
fn reflection_sealer_opener() {
    let props = DefaultProps::default();

    do_test(&props, &mut [0u8; 0]);
    do_test(&props, &mut [0u8; 1]);
    do_test(&props, &mut [0u8; 511]);
    do_test(&props, &mut [0u8; 512]);
    do_test(&props, &mut [0u8; 1008]);
    do_test(&props, &mut [0u8; 1023]);
    do_test(&props, &mut [0u8; 60000]);
}

#[test]
fn corrupt_body() {
    let props = DefaultProps::default();

    let mut content = [0u8; 60000];
    rand::thread_rng().fill_bytes(&mut content);

    block_on(async {
        let mut buf = seal(&props, &content).await;
        buf[1000] += 0x02;
        let (dst, valid) = unseal(&props, &buf).await;

        assert_ne!(&content.as_ref(), &dst.as_slice());
        assert!(!valid);
    })
}

#[test]
fn corrupt_hmac() {
    let props = DefaultProps::default();

    let mut content = [0u8; 60000];
    rand::thread_rng().fill_bytes(&mut content);

    block_on(async {
        let mut buf = seal(&props, &content).await;
        let mutation_point = buf.len() - 5;
        buf[mutation_point] += 0x02;
        let (dst, valid) = unseal(&props, &buf).await;

        assert_eq!(&content.as_ref(), &dst.as_slice());
        assert!(!valid);
    })
}
