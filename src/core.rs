//! FROST2 / FROST2-variant core logic (curve-agnostic).
//!
//! Implements threshold Schnorr signing flow:
//! - Setup / Distibuted key generation (DKG) with Shamir sharing
//! - SPP: per-signer preprocessing token generation
//! - LR: leader request construction
//! - PS: partial signing by each signer
//! - Agg: aggregation into a single Schnorr signature (R, z)
//! - Vf: standard Schnorr verification

use crate::backend::{int_to_bytes_be, lagrange_coeff_at_zero, rand_scalar_nonzero, GroupPoint, Ristretto255GroupAdapter};
use curve25519_dalek::scalar::Scalar;
use std::collections::BTreeMap;

#[derive(Clone)]
pub struct SignerState {
    pub signer_id: u32,
    pub sk_share: Scalar,
    pub pk_share: GroupPoint,
}

#[derive(Clone)]
pub struct PreprocessToken {
    pub r: GroupPoint,
    pub s: GroupPoint,
    pub d: Scalar,
    pub s_scalar: Scalar,
    pub u: Option<Scalar>,
    pub v: Option<GroupPoint>,
}

#[derive(Clone)]
pub struct LeaderRequest {
    pub message: Vec<u8>,
    pub signer_ids: Vec<u32>,
    pub tokens: BTreeMap<u32, (GroupPoint, GroupPoint)>,
}

#[derive(Clone)]
pub struct PartialSignature {
    pub signer_id: u32,
    pub z_i: Scalar,
    pub r: GroupPoint,
}

#[derive(Clone)]
pub struct GroupSignature {
    pub r: GroupPoint,
    pub z: Scalar,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FrostVariant {
    Frost2,
    Frost2Plus,
    Frost2Hash,
}

pub struct Frost2Core {
    pub group: Ristretto255GroupAdapter,
    pub variant: FrostVariant,
}

impl Frost2Core {
    pub fn new(group: Ristretto255GroupAdapter, variant: FrostVariant) -> Self {
        Self { group, variant }
    }

    pub fn keygen_centralized(
        &self,
        n: u32,
        t: u32,
        rng: &mut crate::backend::ExperimentRng,
    ) -> (BTreeMap<u32, SignerState>, GroupPoint) {
        if !(1..=n).contains(&t) {
            panic!("Require 1 <= t <= n");
        }

        let x = rand_scalar_nonzero(rng);
        let mut coeffs = vec![x];
        for _ in 0..(t - 1) {
            coeffs.push(rand_scalar_nonzero(rng));
        }

        let y = self.group.point_mul_base(&x);

        let mut states = BTreeMap::new();
        for i in 1..=n {
            let s_i = eval_poly(&coeffs, i);
            let y_i = self.group.point_mul_base(&s_i);
            states.insert(
                i,
                SignerState {
                    signer_id: i,
                    sk_share: s_i,
                    pk_share: y_i,
                },
            );
        }
        (states, y)
    }

    const DST_KEYGEN_POK: &[u8] = b"FROST_KEYGEN_POK_SHA512";

    pub fn keygen_dkg(
        &self,
        n: u32,
        t: u32,
        rng: &mut crate::backend::ExperimentRng,
        ctx_phi: &str,
    ) -> (BTreeMap<u32, SignerState>, GroupPoint) {
        if !(1..=n).contains(&t) {
            panic!("Require 1 <= t <= n");
        }

        let ctx_bytes = ctx_phi.as_bytes();

        // ----- Round 1 -----
        let mut a_coeffs: BTreeMap<u32, Vec<Scalar>> = BTreeMap::new();
        let mut c_tilde: BTreeMap<u32, Vec<GroupPoint>> = BTreeMap::new();
        let mut sigma: BTreeMap<u32, (GroupPoint, Scalar)> = BTreeMap::new();

        for i in 1..=n {
            let mut a = Vec::with_capacity(t as usize);
            for _ in 0..t {
                a.push(rand_scalar_nonzero(rng));
            }
            let mut ct = Vec::with_capacity(t as usize);
            for aij in &a {
                ct.push(self.group.point_mul_base(aij));
            }
            a_coeffs.insert(i, a.clone());
            c_tilde.insert(i, ct.clone());

            // Schnorr PoK of a_i0
            let k = rand_scalar_nonzero(rng);
            let r = self.group.point_mul_base(&k);
            let phi_i0 = ct[0];
            let i_bytes = int_to_bytes_be(i as u64, 4);
            let parts: Vec<&[u8]> = vec![&i_bytes, ctx_bytes, &phi_i0, &r];
            let c = self.group.hash_to_scalar_nonzero(Self::DST_KEYGEN_POK, &parts);
            let mu = k + a[0] * c;
            sigma.insert(i, (r, mu));
        }

        // Round 1 Step 5: verify all PoKs
        for i in 1..=n {
            for dealer_id in 1..=n {
                if dealer_id == i {
                    continue;
                }
                let (r, mu) = sigma.get(&dealer_id).unwrap();
                let phi_l0 = c_tilde.get(&dealer_id).unwrap()[0];
                let d_bytes = int_to_bytes_be(dealer_id as u64, 4);
                let parts: Vec<&[u8]> = vec![&d_bytes, ctx_bytes, &phi_l0, r];
                let c = self.group.hash_to_scalar_nonzero(Self::DST_KEYGEN_POK, &parts);
                let g_mu = self.group.point_mul_base(&mu);
                let cphi = self.group.point_mul(&phi_l0, &c);
                let right = self.group.point_sub(&g_mu, &cphi);
                if !self.group.point_eq(r, &right) {
                    panic!("PoK verification failed at P{} for dealer P{}", i, dealer_id);
                }
            }
        }

        // ----- Round 2 -----
        let mut mailbox: BTreeMap<u32, BTreeMap<u32, Scalar>> = BTreeMap::new();
        for j in 1..=n {
            mailbox.insert(j, BTreeMap::new());
        }
        for dealer_id in 1..=n {
            let a = a_coeffs.get(&dealer_id).unwrap();
            for receiver_id in 1..=n {
                let share = eval_poly(a, receiver_id);
                mailbox.get_mut(&receiver_id).unwrap().insert(dealer_id, share);
            }
        }
        a_coeffs.clear();

        // Feldman verify and finalize
        let mut states = BTreeMap::new();
        for receiver_id in 1..=n {
            for dealer_id in 1..=n {
                let ct_dealer = c_tilde.get(&dealer_id).unwrap();
                let share_val = mailbox.get(&receiver_id).unwrap().get(&dealer_id).unwrap();
                let left = self.group.point_mul_base(share_val);
                let mut rhs = self.group.identity();
                let mut power = Scalar::ONE;
                for phi_k in ct_dealer {
                    let term = self.group.point_mul(phi_k, &power);
                    rhs = self.group.point_add(&rhs, &term);
                    power *= Scalar::from(receiver_id as u64);
                }
                if !self.group.point_eq(&left, &rhs) {
                    panic!(
                        "Share verification failed at P{} for dealer P{}",
                        receiver_id, dealer_id
                    );
                }
            }

            let mut s_i = Scalar::ZERO;
            for dealer_id in 1..=n {
                s_i += mailbox.get(&receiver_id).unwrap().get(&dealer_id).unwrap();
            }
            let y_i = self.group.point_mul_base(&s_i);
            states.insert(
                receiver_id,
                SignerState {
                    signer_id: receiver_id,
                    sk_share: s_i,
                    pk_share: y_i,
                },
            );
        }

        // Group public key Y = Σ φ_{j0}
        let mut y = self.group.identity();
        for j in 1..=n {
            y = self.group.point_add(&y, &c_tilde.get(&j).unwrap()[0]);
        }

        (states, y)
    }

    pub fn spp_preprocess(
        &self,
        state: &SignerState,
        rng: &mut crate::backend::ExperimentRng,
    ) -> PreprocessToken {
        let d = rand_scalar_nonzero(rng);
        let s_scalar = rand_scalar_nonzero(rng);
        let r = self.group.point_mul_base(&d);
        let s = self.group.point_mul_base(&s_scalar);

        if self.variant == FrostVariant::Frost2 {
            return PreprocessToken {
                r,
                s,
                d,
                s_scalar,
                u: None,
                v: None,
            };
        }

        let mut transcript = int_to_bytes_be(state.signer_id as u64, 4);
        transcript.extend_from_slice(&r);
        transcript.extend_from_slice(&s);

        let domain = b"FROST2P_HPP";
        let parts: Vec<&[u8]> = vec![&transcript];
        let e = self.group.hash_to_scalar_nonzero(domain, &parts);
        let u = rand_scalar_nonzero(rng) + e;
        let v = self.group.point_mul_base(&u);

        PreprocessToken {
            r,
            s,
            d,
            s_scalar,
            u: Some(u),
            v: Some(v),
        }
    }

    pub fn build_leader_request(
        &self,
        message: &[u8],
        signer_ids: &[u32],
        tokens: &BTreeMap<u32, PreprocessToken>,
    ) -> LeaderRequest {
        let mut s: Vec<u32> = signer_ids.to_vec();
        s.sort_unstable();

        let mut lr_tokens = BTreeMap::new();
        for &i in &s {
            let tok = tokens.get(&i).expect("token for signer");
            lr_tokens.insert(i, (tok.r, tok.s));
        }
        LeaderRequest {
            message: message.to_vec(),
            signer_ids: s,
            tokens: lr_tokens,
        }
    }

    fn encode_nonce_list(&self, lr: &LeaderRequest) -> Vec<u8> {
        let mut out = Vec::new();
        for &i in &lr.signer_ids {
            let (r_i, s_i) = lr.tokens.get(&i).unwrap();
            out.extend_from_slice(&int_to_bytes_be(i as u64, 4));
            out.extend_from_slice(r_i);
            out.extend_from_slice(s_i);
        }
        out
    }

    pub fn compute_binding_factor(&self, y: &GroupPoint, lr: &LeaderRequest) -> Scalar {
        let transcript = self.encode_nonce_list(lr);
        let domain = b"FROST2_HNON";
        let parts: Vec<&[u8]> = vec![y, lr.message.as_slice(), transcript.as_slice()];
        self.group.hash_to_scalar_nonzero(domain, &parts)
    }

    pub fn compute_group_commitment(&self, a: &Scalar, lr: &LeaderRequest) -> GroupPoint {
        let mut r = self.group.identity();
        for &i in &lr.signer_ids {
            let (r_i, s_i) = lr.tokens.get(&i).unwrap();
            let term = self.group.point_add(r_i, &self.group.point_mul(s_i, a));
            r = self.group.point_add(&r, &term);
        }
        r
    }

    pub fn compute_challenge(&self, y: &GroupPoint, r: &GroupPoint, message: &[u8]) -> Scalar {
        let domain = b"FROST2_HSIG";
        let parts: Vec<&[u8]> = vec![y, r, message];
        self.group.hash_to_scalar_nonzero(domain, &parts)
    }

    pub fn partial_sign(
        &self,
        state: &SignerState,
        token: &PreprocessToken,
        y: &GroupPoint,
        lr: &LeaderRequest,
    ) -> PartialSignature {
        if !lr.signer_ids.contains(&state.signer_id) {
            panic!("Signer not in leader request's signer set");
        }

        let a = self.compute_binding_factor(y, lr);
        let r = self.compute_group_commitment(&a, lr);
        let c = self.compute_challenge(y, &r, &lr.message);

        let lam_i = lagrange_coeff_at_zero(state.signer_id, &lr.signer_ids);

        if self.variant == FrostVariant::Frost2Plus || self.variant == FrostVariant::Frost2Hash {
            if token.u.is_none() || token.v.is_none() {
                panic!("FROST2+/# token missing authentication fields");
            }
        }

        let mut z_i = token.d;
        z_i += a * token.s_scalar;
        z_i += lam_i * (state.sk_share * c);

        PartialSignature {
            signer_id: state.signer_id,
            z_i,
            r,
        }
    }

    pub fn aggregate(
        &self,
        y: &GroupPoint,
        lr: &LeaderRequest,
        partials: &[PartialSignature],
    ) -> GroupSignature {
        if partials.is_empty() {
            panic!("No partial signatures provided");
        }

        let r_ref = &partials[0].r;
        for ps in partials.iter().skip(1) {
            if !self.group.point_eq(&ps.r, r_ref) {
                panic!("Mismatched group commitment R across partials");
            }
        }

        let _c = self.compute_challenge(y, r_ref, &lr.message);
        let mut z = Scalar::ZERO;
        for ps in partials {
            z += ps.z_i;
        }

        GroupSignature {
            r: *r_ref,
            z,
        }
    }

    pub fn verify(&self, y: &GroupPoint, sig: &GroupSignature, message: &[u8]) -> bool {
        let c = self.compute_challenge(y, &sig.r, message);
        let left = self.group.point_mul_base(&sig.z);
        let right = self.group.point_add(&sig.r, &self.group.point_mul(y, &c));
        self.group.point_eq(&left, &right)
    }

    pub fn share_val(
        &self,
        y: &GroupPoint,
        signer_ids: &[u32],
        signer_states: &BTreeMap<u32, SignerState>,
        i: u32,
        lr: &LeaderRequest,
        sigma_i: &Scalar,
        message: &[u8],
    ) -> bool {
        if !signer_ids.contains(&i) || !signer_states.contains_key(&i) {
            return false;
        }
        let (r_i, s_i) = lr.tokens.get(&i).unwrap();
        let a = self.compute_binding_factor(y, lr);
        let r = self.compute_group_commitment(&a, lr);
        let c = self.compute_challenge(y, &r, message);
        let lam_i = lagrange_coeff_at_zero(i, signer_ids);
        let x_i = &signer_states.get(&i).unwrap().pk_share;

        let lhs = self.group.point_mul_base(sigma_i);
        let rhs1 = self.group.point_add(r_i, &self.group.point_mul(s_i, &a));
        let rhs = self.group.point_add(
            &rhs1,
            &self.group.point_mul(x_i, &(c * lam_i)),
        );
        self.group.point_eq(&lhs, &rhs)
    }
}

fn eval_poly(coeffs: &[Scalar], x: u32) -> Scalar {
    let mut acc = Scalar::ZERO;
    let mut power = Scalar::ONE;
    let x_s = Scalar::from(x as u64);
    for a_j in coeffs {
        acc += a_j * power;
        power *= x_s;
    }
    acc
}
