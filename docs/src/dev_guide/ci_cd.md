# Industrial CI/CD Pipeline
<div class="warning">
This pipeline is designed for <strong>Critical Infrastructure</strong> deployments. Do not bypass security gates.
</div>

## Philosophy: "The Assembly Line"
Just as a physical manufacturing line has quality control stations, our software supply chain has strict automated gates. The `industrial_ci.yml` workflow implements a **Zero Trust** approach to build engineering.

### Stages

#### 1. 🛡️ Security & Compliance Gate
Before any code is built, it must pass the "Gatekeeper":
- **Supply Chain Audit**: Runs `cargo audit` to check against the RustSec Advisory Database.
- **Static Analysis**: Enforces `cargo clippy` with `-D warnings`. No lint warnings are allowed in production code.
- **Formatting**: Enforces strict `rustfmt` rules.

#### 2. 🧪 Test Matrix (Cross-Architecture)
We verify correctness across different computing layers:
- **x86_64 (Gateway/Cloud)**: Runs the full integration test suite, including simulated TPM and network latencies.
- **ARM Thumbv7em (Sensor/Embedded)**: Performs a `cargo check` for the embedded target to ensure `no_std` compliance and correct feature gating.

#### 3. 📦 Industrial Release Build
Only runs on tagged releases (`v*`).
- **Optimization**: Builds with `--release`.
- **Hardening**: Strips debug symbols to reduce attack surface and binary size.
- **SBOM**: Generates a **Software Bill of Materials (SBOM)** in CycloneDX format. This is mandatory for many regulatory standards (EO 14028).
- **Artifacts**: Bundles the binary, the SBOM, and the NIST Compliance Statement into a GitHub Release.

## How to Run Locally

You can simulate the pipeline steps locally:

```bash
# 1. audit
cargo audit

# 2. test (cloud)
cargo test --release

# 3. check (embedded)
rustup target add thumbv7em-none-eabihf
cargo check --target thumbv7em-none-eabihf --no-default-features --features "embedded,kyber,falcon"
```
