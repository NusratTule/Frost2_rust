//! ROAST: Robust Asynchronous Schnorr Threshold Signatures (Ruffing et al., CCS 2022).
//!
//! A wrapper that turns FROST into a robust and asynchronous signing protocol.
//! Single-process simulation for proof-of-concept and benchmarking.

use crate::backend::{ExperimentRng, Ristretto255GroupAdapter};
use crate::core::{Frost2Core, FrostVariant, GroupSignature, LeaderRequest, PartialSignature, PreprocessToken, SignerState};
use std::collections::{BTreeMap, BTreeSet};

pub struct SignerSim {
    pub signer_id: u32,
    pub state: SignerState,
    pub token: Option<PreprocessToken>,
    pub is_malicious: bool,
}

impl SignerSim {
    pub fn pre_round(
        &mut self,
        core: &Frost2Core,
        rng: &mut ExperimentRng,
    ) -> ([u8; 32], [u8; 32]) {
        self.token = Some(core.spp_preprocess(&self.state, rng));
        let tok = self.token.as_ref().unwrap();
        (tok.r, tok.s)
    }

    pub fn sign_round(
        &mut self,
        core: &Frost2Core,
        y: &[u8; 32],
        lr: &LeaderRequest,
        rng: &mut ExperimentRng,
    ) -> Option<(curve25519_dalek::scalar::Scalar, PreprocessToken)> {
        if self.is_malicious {
            return None;
        }
        let token = self.token.as_ref()?;
        let ps = core.partial_sign(&self.state, token, y, lr);
        let new_token = core.spp_preprocess(&self.state, rng);
        Some((ps.z_i, new_token))
    }
}

pub fn run_roast(
    group: Ristretto255GroupAdapter,
    n: u32,
    t: u32,
    message: &[u8],
    seed: Option<u64>,
    num_malicious: u32,
) -> (GroupSignature, std::collections::HashMap<String, f64>) {
    use std::time::Instant;

    let mut timings = std::collections::HashMap::new();

    let t_setup = Instant::now();
    let mut rng = group.new_rng(seed);
    let core = Frost2Core::new(group, FrostVariant::Frost2);
    timings.insert(
        "setup_ms".to_string(),
        t_setup.elapsed().as_secs_f64() * 1000.0,
    );

    let t_keygen = Instant::now();
    let (signer_states, y) = core.keygen_dkg(n, t, &mut rng, "FROST2-DKG");
    timings.insert(
        "keygen_ms".to_string(),
        t_keygen.elapsed().as_secs_f64() * 1000.0,
    );

    let mut malicious_ids = BTreeSet::new();
    if num_malicious > 0 {
        let population: Vec<u32> = (1..=n).collect();
        let sample = rng.sample(&population, num_malicious.min(n - t) as usize);
        for id in sample {
            malicious_ids.insert(id);
        }
    }

    let mut signers: BTreeMap<u32, SignerSim> = BTreeMap::new();
    for i in 1..=n {
        signers.insert(
            i,
            SignerSim {
                signer_id: i,
                state: signer_states.get(&i).unwrap().clone(),
                token: None,
                is_malicious: malicious_ids.contains(&i),
            },
        );
    }

    let mut p: BTreeMap<u32, ([u8; 32], [u8; 32])> = BTreeMap::new();
    let mut r: BTreeSet<u32> = BTreeSet::new();
    let mut m: BTreeSet<u32> = BTreeSet::new();
    let mut sidctr: u32 = 0;
    let mut t_map: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    let mut n_map: BTreeMap<u32, LeaderRequest> = BTreeMap::new();
    let mut s_map: BTreeMap<u32, BTreeMap<u32, curve25519_dalek::scalar::Scalar>> = BTreeMap::new();
    let mut sid_map: BTreeMap<u32, Option<u32>> = (1..=n).map(|i| (i, None)).collect();

    let t_roast_start = Instant::now();

    for i in 1..=n {
        if m.contains(&i) {
            continue;
        }
        let rho_i = signers.get_mut(&i).unwrap().pre_round(&core, &mut rng);
        p.insert(i, rho_i);
        r.insert(i);
    }

    loop {
        if r.len() >= t as usize {
            sidctr += 1;
            let mut chosen: Vec<u32> = r.iter().copied().collect();
            chosen.sort_unstable();
            chosen.truncate(t as usize);

            let mut tokens = BTreeMap::new();
            for &i in &chosen {
                tokens.insert(i, signers.get(&i).unwrap().token.clone().unwrap());
            }
            let lr = core.build_leader_request(message, &chosen, &tokens);
            t_map.insert(sidctr, chosen.clone());
            n_map.insert(sidctr, lr.clone());
            s_map.insert(sidctr, BTreeMap::new());

            for &i in &chosen {
                sid_map.insert(i, Some(sidctr));
            }

            for &i in &chosen {
                r.remove(&i);
            }

            for &i in &chosen {
                if m.contains(&i) {
                    continue;
                }
                let result = signers
                    .get_mut(&i)
                    .unwrap()
                    .sign_round(&core, &y, &lr, &mut rng);
                if let Some((sigma_i, new_token)) = result {
                    if !core.share_val(
                        &y,
                        &chosen,
                        &signer_states,
                        i,
                        &lr,
                        &sigma_i,
                        message,
                    ) {
                        m.insert(i);
                        if m.len() > (n - t) as usize {
                            panic!("Too many malicious signers");
                        }
                        continue;
                    }
                    s_map.get_mut(&sidctr).unwrap().insert(i, sigma_i);
                    signers.get_mut(&i).unwrap().token = Some(new_token.clone());
                    p.insert(i, (new_token.r, new_token.s));
                    r.insert(i);
                } else {
                    m.insert(i);
                    if m.len() > (n - t) as usize {
                        panic!("Too many malicious signers");
                    }
                }
            }

            if s_map.get(&sidctr).unwrap().len() == t as usize {
                let a = core.compute_binding_factor(&y, &lr);
                let r_agg = core.compute_group_commitment(&a, &lr);
                let partials: Vec<PartialSignature> = chosen
                    .iter()
                    .map(|&i| PartialSignature {
                        signer_id: i,
                        z_i: *s_map.get(&sidctr).unwrap().get(&i).unwrap(),
                        r: r_agg,
                    })
                    .collect();
                let sig = core.aggregate(&y, &lr, &partials);
                timings.insert(
                    "roast_total_ms".to_string(),
                    t_roast_start.elapsed().as_secs_f64() * 1000.0,
                );
                timings.insert("sessions_used".to_string(), sidctr as f64);

                if core.verify(&y, &sig, message) {
                    return (sig, timings);
                }
                panic!("ROAST produced invalid signature");
            }
        }

        if r.len() < t as usize && m.len() >= (n - t) as usize {
            panic!("ROAST failed: not enough honest signers");
        }

        if sidctr >= n - t + 1 {
            panic!("ROAST exceeded max sessions");
        }

        if r.len() < t as usize && sidctr > 0 {
            break;
        }
    }

    panic!("ROAST did not complete");
}

pub fn run_roast_simple(
    group: Ristretto255GroupAdapter,
    n: u32,
    t: u32,
    message: &[u8],
    seed: Option<u64>,
) -> (GroupSignature, std::collections::HashMap<String, f64>) {
    run_roast(group, n, t, message, seed, 0)
}
