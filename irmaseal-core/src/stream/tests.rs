use crate::stream::*;
use crate::*;

use arrayvec::ArrayVec;
use futures::io::{Error, ErrorKind};
use futures::task::{Context, Poll};
use rand::RngCore;
use std::pin::Pin;

type BigBuf = ArrayVec<[u8; 65536]>;

struct BifBufWriter {
    big_buf: BigBuf,
}

impl AsyncWrite for BifBufWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let this = &mut *self;
        if this.big_buf.capacity() - this.big_buf.len() < buf.len() {
            Poll::Ready(Err(Error::new(
                ErrorKind::UnexpectedEof,
                "size exceeded max BigBuf length",
            )))
        }
        this.big_buf.extend(buf);
        Poll::Ready(Ok(buf.len()))
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

fn seal<'a>(props: &DefaultProps, content: &[u8]) -> BigBuf {
    let mut rng = rand::thread_rng();
    let DefaultProps { i, pk, sk: _ } = props;

    let mut buf_writer = BifBufWriter {
        big_buf: BigBuf::new(),
    };

    let mut s = Sealer::new(&i, &PublicKey(pk.clone()), &mut rng, &mut buf_writer)
        .await
        .unwrap();
    s.seal(content).unwrap();

    buf_writer.big_buf
}

fn unseal(props: &DefaultProps, buf: &[u8]) -> (BigBuf, bool) {
    let mut rng = rand::thread_rng();
    let DefaultProps { i, pk, sk } = props;

    let (m, o) = OpenerSealed::new(buf).unwrap();
    let i2 = &m.identity;

    assert_eq!(&i, &i2);

    let usk = ibe::kiltz_vahlis_one::extract_usk(&pk, &sk, &i2.derive(), &mut rng);
    let mut dst = BifBufWriter {
        big_buf: BigBuf::new(),
    };
    let validated = o.unseal(&UserSecretKey(usk), &mut dst).unwrap();

    (dst.big_buf, validated)
}

fn seal_and_unseal(props: &DefaultProps, content: &[u8]) -> (BigBuf, bool) {
    let buf = seal(props, content);
    unseal(props, &buf)
}

fn do_test(props: &DefaultProps, content: &mut [u8]) {
    rand::thread_rng().fill_bytes(content);
    let (dst, valid) = seal_and_unseal(props, content);

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

    let mut buf = seal(&props, &content);
    buf[1000] += 0x02;
    let (dst, valid) = unseal(&props, &buf);

    assert_ne!(&content.as_ref(), &dst.as_slice());
    assert!(!valid);
}

#[test]
fn corrupt_hmac() {
    let props = DefaultProps::default();

    let mut content = [0u8; 60000];
    rand::thread_rng().fill_bytes(&mut content);

    let mut buf = seal(&props, &content);
    let mutation_point = buf.len() - 5;
    buf[mutation_point] += 0x02;
    let (dst, valid) = unseal(&props, &buf);

    assert_eq!(&content.as_ref(), &dst.as_slice());
    assert!(!valid);
}
