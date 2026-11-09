//! `wrap MAINPOD.json OUTDIR`: wraps a MainPod that has one public statement
//! into a Groth16-friendly plonky2 proof, and writes the files that
//! `go run cli/main.go -i OUTDIR` reads, plus `public_inputs.json`: the
//! wrapper's 24 public inputs as decimal strings, in the order a contract
//! passes them to the verifier.

use std::{fs, path::Path, time::Instant};

use anyhow::{Context, Result};
use plonky2::field::types::PrimeField64;
use pod2::frontend::MainPod;
use pod2_onchain::{pod::store_files, prepare_public_inputs, prove_pod};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    anyhow::ensure!(args.len() == 3, "usage: wrap MAINPOD.json OUTDIR");
    let pod: MainPod = serde_json::from_str(
        &fs::read_to_string(&args[1]).with_context(|| format!("reading {}", args[1]))?,
    )
    .context("not a MainPod")?;
    let out = Path::new(&args[2]);

    let start = Instant::now();
    let (verifier_data, circuit_data, proof) = prove_pod(pod.clone())?;
    println!("[TIME] wrap took {:?}", start.elapsed());

    let inputs = prepare_public_inputs(&pod)?;
    anyhow::ensure!(proof.public_inputs == inputs, "public inputs differ");
    store_files(out, verifier_data.verifier_only, circuit_data, proof)?;
    let decimal: Vec<String> = inputs
        .iter()
        .map(|f| f.to_canonical_u64().to_string())
        .collect();
    fs::write(
        out.join("public_inputs.json"),
        serde_json::to_string_pretty(&decimal)?,
    )?;
    println!("wrote {}", out.display());
    Ok(())
}
