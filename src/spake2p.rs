use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};
use p256::elliptic_curve::{
    scalar::FromUintUnchecked,
    sec1::{FromEncodedPoint, ToEncodedPoint},
    Curve, Field,
};
use std::ops::Mul;

use crate::util::cryptoutil;

pub struct Context {
    w0: p256::Scalar,
    w1: p256::Scalar,
    x_random: p256::Scalar,
    pub x: p256::EncodedPoint,
    pub y: p256::EncodedPoint,
    pub ca: Option<Vec<u8>>,
    pub decrypt_key: Option<Vec<u8>>,
    pub encrypt_key: Option<Vec<u8>>,
}

pub struct Engine {
    m: p256::AffinePoint,
    n: p256::AffinePoint,
}

impl Engine {
    fn p256_scalar_from_40_bytes(bytes: &[u8]) -> p256::Scalar {
        let int = crypto_bigint::U320::from_be_slice(bytes);
        let modulo = int.rem(&crypto_bigint::NonZero::from_uint(
            crypto_bigint::U320::from(&p256::NistP256::ORDER),
        ));
        let u256 = crypto_bigint::U256::from(&modulo);
        p256::Scalar::from_uint_unchecked(u256)
    }

    fn encoded_point_to_affine(e: &p256::EncodedPoint) -> Result<p256::AffinePoint> {
        let res = p256::AffinePoint::from_encoded_point(e).into_option();
        if let Some(r) = res {
            Ok(r)
        } else {
            Err(anyhow::anyhow!("can't convert point to affine {:?}", e))
        }
    }
    fn encoded_point_to_projective(e: &p256::EncodedPoint) -> Result<p256::ProjectivePoint> {
        let res = p256::ProjectivePoint::from_encoded_point(e).into_option();
        if let Some(r) = res {
            Ok(r)
        } else {
            Err(anyhow::anyhow!(format!(
                "can't convert point to projective {:?}",
                e
            )))
        }
    }

    pub fn create_passcode_verifier(key: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
        let mut kdf = [0; 80];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(key, salt, iterations, &mut kdf);
        let w0 = Self::p256_scalar_from_40_bytes(&kdf[..40]);
        let w1 = Self::p256_scalar_from_40_bytes(&kdf[40..]);
        let l = p256::ProjectivePoint::GENERATOR.mul(w1);
        let mut out = Vec::new();
        out.extend_from_slice(w0.to_bytes().as_slice());
        out.extend_from_slice(l.to_encoded_point(false).as_bytes());
        out
    }

    pub fn start(&self, key: &[u8], salt: &[u8], iterations: u32) -> Result<Context> {
        let mut kdf = [0; 80];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(key, salt, iterations, &mut kdf);

        let w0_scalar = Self::p256_scalar_from_40_bytes(&kdf.as_slice()[..40]);
        let w1_scalar = Self::p256_scalar_from_40_bytes(&kdf[40..80]);

        let x_random_scalar = p256::Scalar::random(rand::thread_rng());

        let t_pp = p256::ProjectivePoint::GENERATOR.mul(x_random_scalar);

        let p = self.m.mul(&w0_scalar);
        let px2 = p.add(&t_pp);

        let px2enc = px2.to_encoded_point(false);
        Ok(Context {
            w0: w0_scalar,
            w1: w1_scalar,
            x_random: x_random_scalar,
            x: px2enc,
            y: p256::EncodedPoint::identity(),
            ca: None,
            decrypt_key: None,
            encrypt_key: None,
        })
    }

    fn append_to_tt(buf: &mut Vec<u8>, data: &[u8]) -> Result<()> {
        buf.write_u64::<LittleEndian>(data.len() as u64)?;
        buf.extend_from_slice(data);
        Ok(())
    }

    pub fn finish(&self, ctx: &mut Context, seed: &[u8]) -> Result<()> {
        let wn = self.n.mul(ctx.w0);
        let wn = wn.neg();
        let zn = Self::encoded_point_to_projective(&ctx.y)?.add(&wn);
        let z = zn.mul(ctx.x_random);
        let v = zn.mul(ctx.w1);

        let result = cryptoutil::sha256(seed);

        let mut tt = Vec::with_capacity(1024);
        Self::append_to_tt(&mut tt, &result)?;
        Self::append_to_tt(&mut tt, &[])?;
        Self::append_to_tt(&mut tt, &[])?;
        Self::append_to_tt(&mut tt, self.m.to_encoded_point(false).as_bytes())?;
        Self::append_to_tt(&mut tt, self.n.to_encoded_point(false).as_bytes())?;
        Self::append_to_tt(&mut tt, ctx.x.as_bytes())?;
        Self::append_to_tt(&mut tt, ctx.y.as_bytes())?;
        Self::append_to_tt(&mut tt, z.to_encoded_point(false).as_bytes())?;
        Self::append_to_tt(&mut tt, v.to_encoded_point(false).as_bytes())?;
        Self::append_to_tt(&mut tt, ctx.w0.to_bytes().as_slice())?;

        let result = cryptoutil::sha256(&tt);
        let ka = &result[..16];
        let ke = &result[16..32];

        let okm = cryptoutil::hkdf_sha256(&[], ka, "ConfirmationKeys".as_bytes(), 32)?;

        ctx.ca = Some(cryptoutil::hmac_sha256(ctx.y.as_bytes(), &okm[..16])?);
        let _cb = cryptoutil::hmac_sha256(ctx.x.as_bytes(), &okm[16..])?;

        let xcrypt = cryptoutil::hkdf_sha256(&[], ke, "SessionKeys".as_bytes(), 16 * 3)?;
        ctx.decrypt_key = Some(xcrypt[16..32].to_vec());
        ctx.encrypt_key = Some(xcrypt[..16].to_vec());

        Ok(())
    }

    pub fn new() -> Result<Self> {
        let mhex = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
        let mbin = hex::decode(mhex)?;
        let m = p256::EncodedPoint::from_bytes(mbin)?;
        let m = Self::encoded_point_to_affine(&m)?;

        let nhex = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";
        let nbin = hex::decode(nhex)?;
        let n = p256::EncodedPoint::from_bytes(nbin)?;
        let n = Self::encoded_point_to_affine(&n)?;
        Ok(Self { m, n })
    }
}
