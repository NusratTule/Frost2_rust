//! Ristretto255 backend adapter for FROST2 variants.
//!
//! Uses curve25519-dalek for Ristretto255 + SHA-512.
//! Points use 32-byte canonical encodings (RFC 9496).

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::seq::SliceRandom;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha512};

/// 32-byte point encoding
pub type GroupPoint = [u8; 32];

/// Identity point (Ristretto encoding of identity)
pub fn ristretto_identity() -> GroupPoint {
    CompressedRistretto::identity().to_bytes()
}

/// Convert integer to big-endian bytes (zero-padded to length)
pub fn int_to_bytes_be(x: u64, length: usize) -> Vec<u8> {
    let mut buf = vec![0u8; length];
    let bytes = x.to_be_bytes();
    if length <= 8 {
        let start = 8 - length;
        buf.copy_from_slice(&bytes[start..8]);
    } else {
        buf[length - 8..].copy_from_slice(&bytes);
    }
    buf
}

/// Reproducible RNG for benchmarking
pub struct ExperimentRng {
    inner: ChaCha20Rng,
}

impl ExperimentRng {
    pub fn new(seed: Option<u64>) -> Self {
        let inner = match seed {
            Some(s) => ChaCha20Rng::seed_from_u64(s),
            None => ChaCha20Rng::seed_from_u64(rand::random()),
        };
        Self { inner }
    }

    pub fn randbelow(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        self.inner.gen_range(0..n)
    }

    pub fn sample(&mut self, population: &[u32], k: usize) -> Vec<u32> {
        let mut pop = population.to_vec();
        pop.shuffle(&mut self.inner);
        pop.into_iter().take(k).collect()
    }

    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
    }
}

/// Hash to scalar (non-zero) with domain separation
pub fn hash_to_scalar_nonzero_sha512(domain: &[u8], parts: &[&[u8]]) -> Scalar {
    let mut ctr: u32 = 0;
    loop {
        let mut h = Sha512::new();
        h.update(domain);
        h.update(&[0u8]);
        h.update(&ctr.to_be_bytes());
        for p in parts {
            h.update(&(p.len() as u32).to_be_bytes());
            h.update(p);
        }
        let digest = h.finalize();
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&digest);
        let s = Scalar::from_bytes_mod_order_wide(&bytes);
        if s != Scalar::ZERO {
            return s;
        }
        ctr += 1;
    }
}

/// Evaluate polynomial f(x) = sum a_j * x^j mod L
pub fn eval_poly(coeffs: &[Scalar], x: u32) -> Scalar {
    let mut acc = Scalar::ZERO;
    let mut power = Scalar::ONE;
    let x_s = Scalar::from(x as u64);
    for a_j in coeffs {
        acc += a_j * power;
        power *= x_s;
    }
    acc
}

/// Lagrange coefficient λ_i at 0 over set S
pub fn lagrange_coeff_at_zero(i: u32, s: &[u32]) -> Scalar {
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    let i_s = Scalar::from(i as u64);
    for &j in s {
        if j == i {
            continue;
        }
        let j_s = Scalar::from(j as u64);
        num *= Scalar::ZERO - j_s;
        den *= i_s - j_s;
    }
    num * den.invert()
}

/// Sample random non-zero scalar
pub fn rand_scalar_nonzero(rng: &mut ExperimentRng) -> Scalar {
    loop {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let s = Scalar::from_bytes_mod_order_wide(&bytes);
        if s != Scalar::ZERO {
            return s;
        }
    }
}

fn decompress_point(bytes: &GroupPoint) -> RistrettoPoint {
    let c = CompressedRistretto::from_slice(bytes).expect("32 bytes");
    c.decompress().expect("valid Ristretto point")
}

/// Ristretto255 group adapter
#[derive(Clone, Copy)]
pub struct Ristretto255GroupAdapter;

impl Ristretto255GroupAdapter {
    pub fn new_rng(&self, seed: Option<u64>) -> ExperimentRng {
        ExperimentRng::new(seed)
    }

    pub fn scalar_add(&self, a: Scalar, b: Scalar) -> Scalar {
        a + b
    }

    pub fn scalar_mul(&self, a: Scalar, b: Scalar) -> Scalar {
        a * b
    }

    pub fn rand_scalar_nonzero(&self, rng: &mut ExperimentRng) -> Scalar {
        rand_scalar_nonzero(rng)
    }

    pub fn lagrange_coeff_at_zero(&self, i: u32, s: &[u32]) -> Scalar {
        lagrange_coeff_at_zero(i, s)
    }

    pub fn point_add(&self, p: &GroupPoint, q: &GroupPoint) -> GroupPoint {
        let p_pt = decompress_point(p);
        let q_pt = decompress_point(q);
        (p_pt + q_pt).compress().to_bytes()
    }

    pub fn point_sub(&self, p: &GroupPoint, q: &GroupPoint) -> GroupPoint {
        let p_pt = decompress_point(p);
        let q_pt = decompress_point(q);
        (p_pt - q_pt).compress().to_bytes()
    }

    pub fn point_mul_base(&self, k: &Scalar) -> GroupPoint {
        if k == &Scalar::ZERO {
            return ristretto_identity();
        }
        RistrettoPoint::mul_base(k).compress().to_bytes()
    }

    pub fn point_mul(&self, p: &GroupPoint, k: &Scalar) -> GroupPoint {
        if k == &Scalar::ZERO {
            return ristretto_identity();
        }
        let p_pt = decompress_point(p);
        (p_pt * k).compress().to_bytes()
    }

    pub fn point_to_bytes(&self, p: &GroupPoint) -> GroupPoint {
        *p
    }

    pub fn point_eq(&self, p: &GroupPoint, q: &GroupPoint) -> bool {
        p == q
    }

    pub fn identity(&self) -> GroupPoint {
        ristretto_identity()
    }

    pub fn hash_to_scalar_nonzero(&self, domain: &[u8], parts: &[&[u8]]) -> Scalar {
        hash_to_scalar_nonzero_sha512(domain, parts)
    }
}
