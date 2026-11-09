# pod2-onchain
Prove POD2s onchain in Ethereum.

## Branch `port-pod2-331a1145`

Ports the wrapper to pod2 `331a1145` and plonky2 `60e32369`, the revisions
digital-objects-network v0.1.0-rc.50 builds with. Since pod2#514 a MainPod
commits to its public statements as the root of an `Array` of their hashes,
and its proof's public inputs are `[statements_root, vds_root, is_main]`, so
the old flat statements hash, the SHA-256 copy and the `gamma` check no longer
apply.

The wrapper (`src/pod.rs`) now takes a MainPod with exactly one public
statement whose arguments are literal values. It verifies the MainPod proof
against the MainPod circuit (a constant), fixes `vds_root` to
`DEFAULT_VD_SET`'s root and `is_main` to 1, rebuilds the statement from the
public inputs, and requires `kv_hash(0, hash(statement))`, the root of the
one-element array, to be the proof's statements root. Its 24 public inputs
are the predicate's hash and each of the 5 arguments' values (4 limbs each),
which a contract reads directly, with no hashing in Solidity.

Also: `src/bin/wrap.rs` (`wrap MAINPOD.json OUTDIR` writes the files
`cli/main.go -i OUTDIR` reads), `solidity_calldata.json` from the Go prover
(the arguments of the generated `verifyProof`), and the CoreFoundation and
Security frameworks linked on macOS, which the cgo archive needs there. The
prover's `[solidity] inputs` read the public witness without skipping its
12-byte header, so every input was off by 12 bytes; fixed.

Measured on 2026-11-09 on an M3 Pro, with a real Bitcraft item's pod (one
`Holds` statement, from bitcraft-leaderboard's `holdings onchain-pod`):

| Step | Time | Peak memory |
|---|---:|---:|
| wrapper proof (circuit 2^13 rows) | 7.7 s, 11.7 s with building the circuit | 1.6 GB |
| Groth16 circuit | 5,567,234 constraints, compiled in 50 s | |
| Groth16 setup | about 17 min | about 9.3 GB (sampled) |
| Groth16 proof | 36.6 s, after 236 s loading the 1.36 GB proving key | 11.2 GB |
| `verifyProof` on-chain, 24 public inputs | 543,110 gas | |

## Run tests
- FFI test, run: `cargo test --release test_groth_full_flow -- --nocapture`
- CLI test, run: `bash test-cli.sh`
  - alternatively:
    1. generate the pod proof: `cargo test --release test_pod_flow -- --nocapture`
    2. generate the groth16 trusted setup: `go run main.go -t`
    3. generate the groth16 proof: `go run main.go -p`
      - this will also generate the Solidity smart contract, located at
        `outputs/Verifier.sol`, ready to be deployed


## Usage
For an example on how to use the rust lib, check the test [`test_groth_full_flow`](https://github.com/0xPARC/pod2-onchain/blob/main/src/lib.rs)

![](pod2-onchain-diagram.png)



## Benchmarks

In an AMD Ryzen 9 5900XT 16cores linux server:
- plonky2 encapsulation proof: `3.08s`
- groth16 proof: `5.2M` r1cs constraints, `10s`

Wrapper circuit proving times for different pod circuit sizes:

| pod circuit size | pod proving time | wrapper circuit size | wrapper proving time |
|------------------|------------------|----------------------|----------------------|
| 2^16             | 15.8s            | 4784                 | 3.09s                |
| 2^17             | 33.3s            | 5175                 | 3.09s                |
| 2^18             | 73.5s            | 5411                 | 3.09s                |
| 2^19             | 153.8s           | 5646                 | 3.09s                |


## Acknowledgements
This repo relies on the following projects:
- Plonky2: https://github.com/0xPolygonZero/plonky2
- Pod2: https://github.com/0xPARC/pod2
- Gnark: https://github.com/Consensys/gnark
- Gnark plonky2 verifier: https://github.com/succinctlabs/gnark-plonky2-verifier
- For the public inputs onchain verification, we use the approach described at https://eprint.iacr.org/2025/1500 and https://eprint.iacr.org/2024/2099 section 4.2.1.
