//! Wraps a pod2 MainPod's proof into a plonky2 proof that a Groth16 circuit
//! can verify (its Merkle caps and FRI use Poseidon over BN254, which
//! gnark-plonky2-verifier checks), and exposes the pod's public statement as
//! public inputs that a smart contract reads directly.
//!
//! Since pod2#514 a MainPod commits to its public statements as the root of
//! an `Array` of their hashes, and its proof's public inputs are
//! `[statements_root (4), vds_root (4), is_main (1)]`. The wrapper supports a
//! pod with exactly one public statement whose arguments are literal values:
//!
//! 1. it verifies the MainPod proof against the MainPod circuit's verifier
//!    data, a constant, so only a real MainPod passes;
//! 2. it fixes `vds_root` to pod2's `DEFAULT_VD_SET` root and `is_main` to 1,
//!    as `MainPod::verify` checks natively;
//! 3. it rebuilds the statement from the public inputs (its predicate hash,
//!    then each argument's value followed by 4 zeros, which rules out anchored
//!    keys), hashes it, and requires the root of the one-element array,
//!    `kv_hash(0, hash)`, to be the proof's `statements_root`.
//!
//! Public inputs, 24 Goldilocks elements:
//!   0..4    the predicate's hash
//!   4..24   argument i's value at 4 + 4i .. 8 + 4i (zero for absent ones)
//!
//! A contract checks the predicate hash against the one it expects and reads
//! the arguments.

use anyhow::{Result, anyhow, ensure};
use std::fs;
use std::io::Write;
use std::iter;
use std::path::Path;
use std::time::Instant;

use plonky2::{
    field::types::{Field, PrimeField64},
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData, VerifierOnlyCircuitData},
        proof::ProofWithPublicInputs,
    },
};

use pod2::{
    backends::plonky2::{
        basetypes::{C, D, DEFAULT_VD_SET, F},
        circuits::common::ValueTarget,
        mainpod::{
            Prover, cache_get_rec_main_pod_verifier_circuit_data, public_inputs,
            statement::Statement as BStatement, statements_mt,
        },
        primitives::merkletree::{circuit::kv_hash_target, kv_hash},
    },
    frontend::{MainPod, MultiPodBuilder, Operation},
    middleware::{Params, RawValue, Statement, ToFields, Value},
};

use crate::poseidon_bn128::config::PoseidonBN128GoldilocksConfig;

type Bn = PoseidonBN128GoldilocksConfig;

/// Arguments in a statement (`Params::max_statement_args`).
const MAX_ARGS: usize = 5;
/// Field elements per argument: a value's 4, then 4 that are zero for a
/// literal value (`STATEMENT_ARG_F_LEN`).
const ARG_LEN: usize = 8;
/// Field elements of a predicate hash, and of a value.
const HASH_LEN: usize = 4;
/// The wrapper's public inputs: the predicate hash and each argument's value.
pub const NUM_PUBLIC_INPUTS: usize = HASH_LEN + MAX_ARGS * HASH_LEN;

/// The key of the first element of an `Array`.
fn first_key() -> RawValue {
    Value::from(0i64).raw()
}

/// The wrapper's public inputs for `statement`: its predicate hash and its
/// arguments' values. Fails if an argument is an anchored key.
pub fn statement_public_inputs(statement: &Statement) -> Result<Vec<F>> {
    let fields = BStatement::from(statement.clone()).to_fields();
    ensure!(
        fields.len() == HASH_LEN + MAX_ARGS * ARG_LEN,
        "a statement has {} field elements, expected {}",
        fields.len(),
        HASH_LEN + MAX_ARGS * ARG_LEN
    );
    let mut inputs = fields[..HASH_LEN].to_vec();
    for i in 0..MAX_ARGS {
        let arg = &fields[HASH_LEN + i * ARG_LEN..HASH_LEN + (i + 1) * ARG_LEN];
        ensure!(
            arg[HASH_LEN..].iter().all(|f| f.is_zero()),
            "argument {i} of {statement} is not a literal value"
        );
        inputs.extend_from_slice(&arg[..HASH_LEN]);
    }
    Ok(inputs)
}

/// The pod's one public statement.
fn single_statement(pod: &MainPod) -> Result<Statement> {
    let statements = pod.pod.pub_raw_statements();
    ensure!(
        statements.len() == 1,
        "the pod has {} public statements; the wrapper takes exactly one",
        statements.len()
    );
    Ok(statements[0].clone())
}

/// The wrapper's public inputs for `pod`, as `prove_pod` registers them.
pub fn prepare_public_inputs(pod: &MainPod) -> Result<Vec<F>> {
    statement_public_inputs(&single_statement(pod)?)
}

/// Generates the Groth16-friendly plonky2 proof of the given MainPod.
pub fn prove_pod(
    pod: MainPod,
) -> Result<(
    VerifierCircuitData<F, Bn, D>,
    CircuitData<F, Bn, D>,
    ProofWithPublicInputs<F, Bn, D>,
)> {
    let params = pod.pod.params().clone();
    ensure!(params == Params::default(), "the pod uses other circuit parameters");
    ensure!(!pod.pod.is_mock(), "the pod is a mock pod");
    ensure!(
        pod.pod.vd_set().root() == DEFAULT_VD_SET.root(),
        "the pod's verifier data set is not pod2's default"
    );
    pod.pod
        .verify()
        .map_err(|err| anyhow!("the pod does not verify: {err}"))?;

    let statement = single_statement(&pod)?;
    let statement_hash = BStatement::from(statement.clone()).hash();
    ensure!(
        kv_hash(&first_key(), Some(RawValue::from(statement_hash))) == pod.pod.statements_root(),
        "the one-statement root differs from the pod's statements root"
    );
    ensure!(
        statements_mt(&[BStatement::from(statement.clone())]).commitment()
            == pod.pod.statements_root(),
        "statements_mt differs from the pod's statements root"
    );
    let values = statement_public_inputs(&statement)?;

    let inner_verifier_only: VerifierOnlyCircuitData<C, D> = pod.pod.verifier_data();
    let inner_common = cache_get_rec_main_pod_verifier_circuit_data(&params)
        .common
        .clone();
    let inner_proof = pod2::middleware::ProofWithPublicInputs {
        proof: pod.pod.proof(),
        public_inputs: public_inputs(pod.pod.statements_root(), pod.pod.vd_set().root(), true),
    };

    let start = Instant::now();
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

    // 1. the MainPod proof, against the MainPod circuit
    let proof_target = builder.add_virtual_proof_with_pis(&inner_common);
    let verifier_target = builder.constant_verifier_data(&inner_verifier_only);
    builder.verify_proof::<C>(&proof_target, &verifier_target, &inner_common);

    // 2. pod2's default verifier data set, and a main pod
    let vds_root = DEFAULT_VD_SET.root();
    for i in 0..HASH_LEN {
        let root_limb = builder.constant(vds_root.0[i]);
        builder.connect(proof_target.public_inputs[HASH_LEN + i], root_limb);
    }
    let one = builder.one();
    builder.connect(proof_target.public_inputs[2 * HASH_LEN], one);

    // 3. the statement, from the public inputs
    let values_target: Vec<Target> = builder.add_virtual_targets(NUM_PUBLIC_INPUTS);
    builder.register_public_inputs(&values_target);
    let zero = builder.zero();
    let mut fields_target = values_target[..HASH_LEN].to_vec();
    for i in 0..MAX_ARGS {
        let value = &values_target[HASH_LEN + i * HASH_LEN..HASH_LEN + (i + 1) * HASH_LEN];
        fields_target.extend_from_slice(value);
        fields_target.extend(iter::repeat_n(zero, ARG_LEN - HASH_LEN));
    }
    let statement_hash_target = builder.hash_n_to_hash_no_pad::<PoseidonHash>(fields_target);
    let key = first_key();
    let key_target = ValueTarget {
        elements: std::array::from_fn(|i| builder.constant(key.0[i])),
    };
    let root_target = kv_hash_target(
        &mut builder,
        &key_target,
        &ValueTarget {
            elements: statement_hash_target.elements,
        },
    );
    builder.connect_hashes(
        root_target,
        HashOutTarget::from_vec(proof_target.public_inputs[..HASH_LEN].to_vec()),
    );

    let circuit_data = builder.build::<Bn>();
    println!(
        "[TIME] wrapper circuit (2^{} rows) built in {:?}",
        circuit_data.common.degree_bits(),
        start.elapsed()
    );

    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&proof_target, &inner_proof)?;
    pw.set_target_arr(&values_target, &values)?;
    let start = Instant::now();
    let proof = circuit_data.prove(pw)?;
    println!("[TIME] wrapper proof took {:?}", start.elapsed());

    let verifier_data = circuit_data.verifier_data();
    verifier_data.verify(proof.clone())?;
    Ok((verifier_data, circuit_data, proof))
}

/// gets as input the public inputs vector (output from
/// `prepare_public_inputs`), and encodes it as a byte-array compatible with
/// Gnark encoding
pub fn encode_public_inputs_gnark(pub_inp: Vec<F>) -> Vec<u8> {
    // encode it as big-endian bytes compatible with Gnark:
    //   0..4: num public inputs
    //   4..8: num secret inputs (0 in the case of only public inputs))
    //   8..12: num of elements in the vector (which is the num of public inputs)
    //   12..n: public inputs encoded as big-endian bytes
    let mut pub_inp_bytes = Vec::new();
    let n = pub_inp.len() as u32;
    pub_inp_bytes.extend_from_slice(&n.to_be_bytes());
    pub_inp_bytes.extend_from_slice(&0u32.to_be_bytes());
    pub_inp_bytes.extend_from_slice(&n.to_be_bytes());
    for e in pub_inp {
        let b = e.to_canonical_u64().to_be_bytes();
        let padding = vec![0u8; 24];
        let b_256 = [padding, b.to_vec()].concat();
        pub_inp_bytes.extend_from_slice(&b_256);
    }
    pub_inp_bytes
}

pub fn store_files(
    dir: &Path,
    verifier_only_data: VerifierOnlyCircuitData<Bn, D>,
    common_circuit_data: CircuitData<F, Bn, D>,
    proof_with_pis: ProofWithPublicInputs<F, Bn, D>,
) -> Result<()> {
    fs::create_dir_all(dir)?;

    let json = serde_json::to_string_pretty(&verifier_only_data)?;
    let mut file = fs::File::create(dir.join("verifier_only_circuit_data.json"))?;
    file.write_all(&json.into_bytes())?;

    let json = serde_json::to_string_pretty(&proof_with_pis)?;
    let mut file = fs::File::create(dir.join("proof_with_public_inputs.json"))?;
    file.write_all(&json.into_bytes())?;

    let json = serde_json::to_string_pretty(&common_circuit_data.common)?;
    let mut file = fs::File::create(dir.join("common_circuit_data.json"))?;
    file.write_all(&json.into_bytes())?;

    let compressed_proof = proof_with_pis.compress(
        &verifier_only_data.circuit_digest,
        &common_circuit_data.common,
    )?;
    let mut file = fs::File::create(dir.join("proof_with_public_inputs.bin"))?;
    file.write_all(&compressed_proof.to_bytes())?;

    Ok(())
}

/// A MainPod with one public statement, `Equal(42, 42)`.
pub fn sample_main_pod() -> Result<MainPod> {
    let params = Params::default();
    let mut builder = MultiPodBuilder::new(&params, &DEFAULT_VD_SET);
    builder.pub_op(Operation::eq(Value::from(42i64), Value::from(42i64)))?;
    let pod = builder
        .solve()
        .map_err(|err| anyhow!(err))?
        .prove(&Prover {})
        .map_err(|err| anyhow!(err))?
        .output_pod()
        .clone();
    Ok(pod)
}

/// generates and stores a Plonky2 proof which is Groth16 friendly
pub fn sample_plonky2_g16_friendly_proof(path: &str) -> Result<()> {
    // step 1) obtain the pod to be proven
    let start = Instant::now();
    let pod = sample_main_pod()?;
    println!(
        "[TIME] generate pod & compute pod proof took: {:?}",
        start.elapsed()
    );

    // step 2) generate new plonky2 proof from POD's proof
    let start = Instant::now();
    let (verifier_data, common_circuit_data, proof_with_pis) = prove_pod(pod.clone())?;
    println!(
        "[TIME] plonky2 proof (groth16-friendly) took: {:?}",
        start.elapsed()
    );
    assert_eq!(proof_with_pis.public_inputs.len(), NUM_PUBLIC_INPUTS);

    // check that the `prepare_public_inputs` method works as expected
    assert_eq!(proof_with_pis.public_inputs, prepare_public_inputs(&pod)?);

    // step 3) store the files
    store_files(
        Path::new(path),
        verifier_data.verifier_only,
        common_circuit_data,
        proof_with_pis,
    )?;
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_sample_plonky2_g16_friendly_proof() -> Result<()> {
        sample_plonky2_g16_friendly_proof("./tmp/plonky2-proof")
    }

    #[test]
    fn test_public_inputs_layout() -> Result<()> {
        let statement = Statement::Equal(Value::from(42i64).into(), Value::from(7i64).into());
        let inputs = statement_public_inputs(&statement)?;
        assert_eq!(inputs.len(), NUM_PUBLIC_INPUTS);
        assert_eq!(&inputs[4..8], &Value::from(42i64).raw().0);
        assert_eq!(&inputs[8..12], &Value::from(7i64).raw().0);
        assert!(inputs[12..].iter().all(|f| f.is_zero()));
        Ok(())
    }
}
