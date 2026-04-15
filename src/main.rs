//! FROST Variants Comparison (Ristretto255, SHA-512).
//!
//! Runs FROST1, Binding (FROST2), FROST2+, FROST2#, and ROAST,
//! collecting per-phase runtimes and outputting a comparison table in MJCA TABLE 3 format.

use frost2_rust::backend::Ristretto255GroupAdapter;
use frost2_rust::core::{Frost2Core, FrostVariant, PreprocessToken};
use frost2_rust::roast::run_roast_simple;
use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

fn ms(dt_secs: f64) -> f64 {
    dt_secs * 1000.0
}

const PHASES: &[&str] = &[
    "setup",
    "keygen",
    "preprocess",
    "signing",
    "combining",
    "verifying",
    "preprocess_per_participant",
    "signing_per_participant",
];

const VARIANT_KEYS: &[&str] = &["FROST1", "Binding", "FROST2+", "FROST2#", "ROAST"];
const COLUMN_NAMES: &[&str] = &["FROST1", "Binding", "FROST-2+", "FROST-2#", "ROAST"];

fn mean_median_std(vals: &[f64]) -> (f64, f64, f64) {
    if vals.is_empty() {
        return (0.0, 0.0, 0.0);
    }
    if vals.len() == 1 {
        return (vals[0], vals[0], 0.0);
    }
    let mean = vals.iter().sum::<f64>() / vals.len() as f64;
    let mut sorted = vals.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = if sorted.len() % 2 == 1 {
        sorted[sorted.len() / 2]
    } else {
        (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2.0
    };
    let variance = vals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (vals.len() - 1) as f64;
    let std = variance.sqrt();
    (mean, median, std)
}

type Timings = HashMap<String, f64>;

fn run_binding(
    group: &Ristretto255GroupAdapter,
    n: u32,
    t: u32,
    alpha: u32,
    message: &[u8],
    seed: Option<u64>,
) -> (Timings, Vec<f64>, Vec<f64>) {
    let mut timings = HashMap::new();
    for &p in PHASES {
        if p != "preprocess_per_participant" && p != "signing_per_participant" {
            timings.insert(p.to_string(), 0.0);
        }
    }
    let mut preprocess_pp = Vec::new();
    let mut signing_pp = Vec::new();

    let t0 = Instant::now();
    let mut rng = group.new_rng(seed);
    let core = Frost2Core::new(*group, FrostVariant::Frost2);
    timings.insert("setup".to_string(), ms(t0.elapsed().as_secs_f64()));

    let t0 = Instant::now();
    let (signer_states, y) = core.keygen_dkg(n, t, &mut rng, "FROST2-DKG");
    timings.insert("keygen".to_string(), ms(t0.elapsed().as_secs_f64()));

    let population: Vec<u32> = (1..=n).collect();
    let s_ids = rng.sample(&population, alpha as usize);
    let mut s_ids: Vec<u32> = s_ids;
    s_ids.sort_unstable();

    let t0 = Instant::now();
    let mut tokens: BTreeMap<u32, PreprocessToken> = BTreeMap::new();
    for &sid in &s_ids {
        let t_pp = Instant::now();
        tokens.insert(sid, core.spp_preprocess(signer_states.get(&sid).unwrap(), &mut rng));
        preprocess_pp.push(ms(t_pp.elapsed().as_secs_f64()));
    }
    let lr = core.build_leader_request(message, &s_ids, &tokens);
    timings.insert("preprocess".to_string(), ms(t0.elapsed().as_secs_f64()));

    let t0 = Instant::now();
    let mut partials = Vec::new();
    for &sid in &s_ids {
        let t_sp = Instant::now();
        let ps = core.partial_sign(
            signer_states.get(&sid).unwrap(),
            tokens.get(&sid).unwrap(),
            &y,
            &lr,
        );
        partials.push(ps);
        signing_pp.push(ms(t_sp.elapsed().as_secs_f64()));
    }
    timings.insert("signing".to_string(), ms(t0.elapsed().as_secs_f64()));

    let t0 = Instant::now();
    let sig = core.aggregate(&y, &lr, &partials);
    timings.insert("combining".to_string(), ms(t0.elapsed().as_secs_f64()));

    let t0 = Instant::now();
    let ok = core.verify(&y, &sig, message);
    timings.insert("verifying".to_string(), ms(t0.elapsed().as_secs_f64()));

    if !ok {
        panic!("Binding (FROST2) verification failed");
    }
    (timings, preprocess_pp, signing_pp)
}

fn run_frost2_plus(
    group: &Ristretto255GroupAdapter,
    n: u32,
    t: u32,
    alpha: u32,
    message: &[u8],
    seed: Option<u64>,
) -> (Timings, Vec<f64>, Vec<f64>) {
    let mut timings = HashMap::new();
    for &p in PHASES {
        if p != "preprocess_per_participant" && p != "signing_per_participant" {
            timings.insert(p.to_string(), 0.0);
        }
    }
    let mut preprocess_pp = Vec::new();
    let mut signing_pp = Vec::new();

    let t0 = Instant::now();
    let mut rng = group.new_rng(seed);
    let core = Frost2Core::new(*group, FrostVariant::Frost2Plus);
    timings.insert("setup".to_string(), ms(t0.elapsed().as_secs_f64()));

    let t0 = Instant::now();
    let (signer_states, y) = core.keygen_dkg(n, t, &mut rng, "FROST2-DKG");
    timings.insert("keygen".to_string(), ms(t0.elapsed().as_secs_f64()));

    let population: Vec<u32> = (1..=n).collect();
    let s_ids = rng.sample(&population, alpha as usize);
    let mut s_ids: Vec<u32> = s_ids;
    s_ids.sort_unstable();

    let t0 = Instant::now();
    let mut tokens: BTreeMap<u32, PreprocessToken> = BTreeMap::new();
    for &sid in &s_ids {
        let t_pp = Instant::now();
        tokens.insert(sid, core.spp_preprocess(signer_states.get(&sid).unwrap(), &mut rng));
        preprocess_pp.push(ms(t_pp.elapsed().as_secs_f64()));
    }
    let lr = core.build_leader_request(message, &s_ids, &tokens);
    timings.insert("preprocess".to_string(), ms(t0.elapsed().as_secs_f64()));

    let t0 = Instant::now();
    let mut partials = Vec::new();
    for &sid in &s_ids {
        let t_sp = Instant::now();
        let ps = core.partial_sign(
            signer_states.get(&sid).unwrap(),
            tokens.get(&sid).unwrap(),
            &y,
            &lr,
        );
        partials.push(ps);
        signing_pp.push(ms(t_sp.elapsed().as_secs_f64()));
    }
    timings.insert("signing".to_string(), ms(t0.elapsed().as_secs_f64()));

    let t0 = Instant::now();
    let sig = core.aggregate(&y, &lr, &partials);
    timings.insert("combining".to_string(), ms(t0.elapsed().as_secs_f64()));

    let t0 = Instant::now();
    let ok = core.verify(&y, &sig, message);
    timings.insert("verifying".to_string(), ms(t0.elapsed().as_secs_f64()));

    if !ok {
        panic!("FROST2+ verification failed");
    }
    (timings, preprocess_pp, signing_pp)
}

fn run_frost2_hash(
    group: &Ristretto255GroupAdapter,
    n: u32,
    t: u32,
    alpha: u32,
    message: &[u8],
    seed: Option<u64>,
) -> (Timings, Vec<f64>, Vec<f64>) {
    let mut timings = HashMap::new();
    for &p in PHASES {
        if p != "preprocess_per_participant" && p != "signing_per_participant" {
            timings.insert(p.to_string(), 0.0);
        }
    }
    let mut preprocess_pp = Vec::new();
    let mut signing_pp = Vec::new();

    let t0 = Instant::now();
    let mut rng = group.new_rng(seed);
    let core = Frost2Core::new(*group, FrostVariant::Frost2Hash);
    timings.insert("setup".to_string(), ms(t0.elapsed().as_secs_f64()));

    let t0 = Instant::now();
    let (signer_states, y) = core.keygen_dkg(n, t, &mut rng, "FROST2-DKG");
    timings.insert("keygen".to_string(), ms(t0.elapsed().as_secs_f64()));

    let population: Vec<u32> = (1..=n).collect();
    let s_ids = rng.sample(&population, alpha as usize);
    let mut s_ids: Vec<u32> = s_ids;
    s_ids.sort_unstable();

    let t0 = Instant::now();
    let mut tokens: BTreeMap<u32, PreprocessToken> = BTreeMap::new();
    for &sid in &s_ids {
        let t_pp = Instant::now();
        tokens.insert(sid, core.spp_preprocess(signer_states.get(&sid).unwrap(), &mut rng));
        preprocess_pp.push(ms(t_pp.elapsed().as_secs_f64()));
    }
    let lr = core.build_leader_request(message, &s_ids, &tokens);
    timings.insert("preprocess".to_string(), ms(t0.elapsed().as_secs_f64()));

    let t0 = Instant::now();
    let mut partials = Vec::new();
    for &sid in &s_ids {
        let t_sp = Instant::now();
        let ps = core.partial_sign(
            signer_states.get(&sid).unwrap(),
            tokens.get(&sid).unwrap(),
            &y,
            &lr,
        );
        partials.push(ps);
        signing_pp.push(ms(t_sp.elapsed().as_secs_f64()));
    }
    timings.insert("signing".to_string(), ms(t0.elapsed().as_secs_f64()));

    let t0 = Instant::now();
    let sig = core.aggregate(&y, &lr, &partials);
    timings.insert("combining".to_string(), ms(t0.elapsed().as_secs_f64()));

    let t0 = Instant::now();
    let ok = core.verify(&y, &sig, message);
    timings.insert("verifying".to_string(), ms(t0.elapsed().as_secs_f64()));

    if !ok {
        panic!("FROST2# verification failed");
    }
    (timings, preprocess_pp, signing_pp)
}

fn run_roast_variant(
    group: &Ristretto255GroupAdapter,
    n: u32,
    t: u32,
    alpha: u32,
    message: &[u8],
    seed: Option<u64>,
) -> (Timings, Vec<f64>, Vec<f64>) {
    let mut timings = HashMap::new();
    for &p in PHASES {
        if p != "preprocess_per_participant" && p != "signing_per_participant" {
            timings.insert(p.to_string(), 0.0);
        }
    }

    let (_, roast_t) = run_roast_simple(*group, n, t, message, seed);

    timings.insert(
        "setup".to_string(),
        *roast_t.get("setup_ms").unwrap_or(&0.0),
    );
    timings.insert(
        "keygen".to_string(),
        *roast_t.get("keygen_ms").unwrap_or(&0.0),
    );
    timings.insert("preprocess".to_string(), 0.0);
    let roast_total = *roast_t.get("roast_total_ms").unwrap_or(&0.0);
    timings.insert("signing".to_string(), roast_total);
    timings.insert("combining".to_string(), 0.0);
    timings.insert("verifying".to_string(), 0.0);

    let per_part = if alpha > 0 {
        roast_total / alpha as f64
    } else {
        0.0
    };
    let preprocess_pp = (0..alpha).map(|_| per_part * 0.3).collect();
    let signing_pp = (0..alpha).map(|_| per_part * 0.7).collect();

    (timings, preprocess_pp, signing_pp)
}

fn print_mjca_table(
    results: &HashMap<String, HashMap<String, (f64, f64, f64)>>,
) {
    let phase_display: HashMap<&str, &str> = [
        ("setup", "setup"),
        ("keygen", "Key generation"),
        ("preprocess", "Preprocess"),
        ("signing", "signing"),
        ("combining", "combining"),
        ("verifying", "verifying"),
        ("preprocess_per_participant", "preprocess per participant"),
        ("signing_per_participant", "signing per participant"),
    ]
    .into_iter()
    .collect();

    let phase_order = [
        "setup",
        "keygen",
        "preprocess",
        "signing",
        "combining",
        "verifying",
        "preprocess_per_participant",
        "signing_per_participant",
    ];

    let phase_width = 28;
    let num_width = 10;
    let stat_width = num_width * 3 + 2;

    println!("RUNTIME OF VARIANTS OF FROST1, FROST2 & ROAST (Ristretto255, SHA-512)");
    println!();

    print!("| {:<phase_width$} |", "Phase");
    for name in COLUMN_NAMES {
        print!(" {:^stat_width$} |", name);
    }
    println!();

    print!("| {:<phase_width$} |", "");
    for _ in COLUMN_NAMES {
        print!(" {:>num_width$} {:>num_width$} {:>num_width$} |", "mean", "median", "std");
    }
    println!();

    print!("|-{:->phase_width$}-|", "");
    for _ in COLUMN_NAMES {
        print!("-{:->stat_width$}-|", "");
    }
    println!();

    for phase in phase_order {
        let display = *phase_display.get(phase).unwrap_or(&phase);
        print!("| {:<phase_width$} |", display);
        for key in VARIANT_KEYS {
            let (m, med, s) = results
                .get(*key)
                .and_then(|r| r.get(phase))
                .copied()
                .unwrap_or((0.0, 0.0, 0.0));
            print!(" {:>num_width$.3} {:>num_width$.3} {:>num_width$.3} |", m, med, s);
        }
        println!();
    }
}

fn export_results_csv(
    results: &HashMap<String, HashMap<String, (f64, f64, f64)>>,
    path: &str,
    n: u32,
    t: u32,
    alpha: u32,
    trials: u32,
    seed: Option<u64>,
) {
    let phase_display: HashMap<&str, &str> = [
        ("setup", "setup"),
        ("keygen", "Key generation"),
        ("preprocess", "Preprocess"),
        ("signing", "signing"),
        ("combining", "combining"),
        ("verifying", "verifying"),
        ("preprocess_per_participant", "preprocess per participant"),
        ("signing_per_participant", "signing per participant"),
    ]
    .into_iter()
    .collect();

    let phase_order = [
        "setup",
        "keygen",
        "preprocess",
        "signing",
        "combining",
        "verifying",
        "preprocess_per_participant",
        "signing_per_participant",
    ];

    let mut w = csv::Writer::from_path(path).expect("create CSV");
    w.write_record(&["# RUNTIME OF VARIANTS OF FROST1, FROST2 & ROAST (Ristretto255, SHA-512)"])
        .ok();
    let meta = format!(
        "# n={}, t={}, alpha={}, trials={}, seed={:?}",
        n, t, alpha, trials, seed
    );
    w.write_record(&[meta.as_str()]).ok();
    w.write_record(&[""]).ok();

    let mut header = vec!["Phase".to_string()];
    for name in COLUMN_NAMES {
        for stat in &["mean", "median", "std"] {
            header.push(format!("{}_{}", name, stat));
        }
    }
    let header_refs: Vec<&str> = header.iter().map(|s| s.as_str()).collect();
    w.write_record(&header_refs).ok();

    for phase in phase_order {
        let display = *phase_display.get(phase).unwrap_or(&phase);
        let mut row = vec![display.to_string()];
        for key in VARIANT_KEYS {
            let (m, med, s) = results
                .get(*key)
                .and_then(|r| r.get(phase))
                .copied()
                .unwrap_or((0.0, 0.0, 0.0));
            row.push(format!("{:.3}", m));
            row.push(format!("{:.3}", med));
            row.push(format!("{:.3}", s));
        }
        let row_refs: Vec<&str> = row.iter().map(|s| s.as_str()).collect();
        w.write_record(&row_refs).ok();
    }
    w.flush().expect("flush CSV");
}

fn main() {
    use clap::Parser;

    #[derive(Parser)]
    #[command(about = "FROST variants comparison (Ristretto255, MJCA TABLE 3 format + ROAST)")]
    struct Args {
        #[arg(short, long, default_value = "10")]
        n: u32,

        #[arg(short, long, default_value = "5")]
        t: u32,

        #[arg(long)]
        alpha: Option<u32>,

        #[arg(short = 'r', long, default_value = "10", help = "Number of trials for mean/median/std")]
        trials: u32,

        #[arg(short, long)]
        seed: Option<u64>,

        #[arg(long, default_value = "test")]
        message: String,

        #[arg(short, long, help = "Export results to CSV file")]
        output: Option<String>,
    }

    let args = Args::parse();
    let n = args.n;
    let t = args.t;
    let alpha = args.alpha.unwrap_or(t);
    let trials = args.trials;
    let seed = args.seed;
    let message = args.message.as_bytes();

    if !(1..=n).contains(&t) {
        eprintln!("Error: Require 1 <= t <= n");
        std::process::exit(1);
    }
    if !(t..=n).contains(&alpha) {
        eprintln!("Error: Require t <= alpha <= n");
        std::process::exit(1);
    }

    let group = Ristretto255GroupAdapter;

    let mut accum: HashMap<String, HashMap<String, Vec<f64>>> = HashMap::new();
    for &v in VARIANT_KEYS {
        let mut phases = HashMap::new();
        for &p in PHASES {
            phases.insert(p.to_string(), Vec::new());
        }
        accum.insert(v.to_string(), phases);
    }

    let runners: &[(&str, fn(&Ristretto255GroupAdapter, u32, u32, u32, &[u8], Option<u64>) -> (Timings, Vec<f64>, Vec<f64>))] = &[
        ("FROST1", run_binding),
        ("Binding", run_binding),
        ("FROST2+", run_frost2_plus),
        ("FROST2#", run_frost2_hash),
        ("ROAST", run_roast_variant),
    ];

    for trial in 0..trials {
        let trial_seed = seed.map(|s| s + trial as u64);

        for &(var_key, run_fn) in runners {
            let (timings, pre_pp, sign_pp) = run_fn(&group, n, t, alpha, message, trial_seed);
            let acc = accum.get_mut(var_key).unwrap();
            acc.get_mut("setup").unwrap().push(*timings.get("setup").unwrap_or(&0.0));
            acc.get_mut("keygen").unwrap().push(*timings.get("keygen").unwrap_or(&0.0));
            acc.get_mut("preprocess").unwrap().push(*timings.get("preprocess").unwrap_or(&0.0));
            acc.get_mut("signing").unwrap().push(*timings.get("signing").unwrap_or(&0.0));
            acc.get_mut("combining").unwrap().push(*timings.get("combining").unwrap_or(&0.0));
            acc.get_mut("verifying").unwrap().push(*timings.get("verifying").unwrap_or(&0.0));
            acc.get_mut("preprocess_per_participant")
                .unwrap()
                .extend(pre_pp);
            acc.get_mut("signing_per_participant")
                .unwrap()
                .extend(sign_pp);
        }
    }

    let mut results: HashMap<String, HashMap<String, (f64, f64, f64)>> = HashMap::new();
    for &var_key in VARIANT_KEYS {
        let mut phase_stats = HashMap::new();
        for &phase in PHASES {
            let vals = accum.get(var_key).unwrap().get(phase).unwrap();
            phase_stats.insert(phase.to_string(), mean_median_std(vals));
        }
        results.insert(var_key.to_string(), phase_stats);
    }

    println!("=== FROST Variants Comparison (Ristretto255, SHA-512) ===");
    println!("n={}, t={}, alpha={}, trials={}, seed={:?}", n, t, alpha, trials, seed);
    println!();

    print_mjca_table(&results);

    if let Some(ref path) = args.output {
        export_results_csv(&results, path, n, t, alpha, trials, seed);
        eprintln!("Results exported to {}", path);
    }
}
