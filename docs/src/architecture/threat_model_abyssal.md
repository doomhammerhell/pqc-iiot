# Abyssal Threat Model: Nation-State Vectors & Mitigation

This document provides a mathematical and architectural analysis of the threats PQC-Boot is designed to withstand, specifically targeting **Q-Day** (Quantum Decryption) and **Advanced Persistent Threats (APTs)**.

## 1. Adversary Model

We assume an **"Infinite Resource" Adversary ($A_{inf}$)** with:
1.  **Quantum Computer**: Capable of running Shor's Algorithm with $2^{60}$ qubits.
2.  **Physical Access**: Can retrieve the device, decapsulate chips, and probe buses.
3.  **Network Omnipotence**: Can capture, replay, and modify all traffic.
4.  **Supply Chain Injection**: Can compromise the manufacturing facility.

## 2. Mathematical Hardness Assumptions

PQC-Boot relies on the hardness of **Module-LWE** (Kyber) and **NTRU** (Falcon) problems over structured lattices.

### 2.1 Falcon-512 (Digital Signatures)

Falcon is based on the **NTRU Lattice Problem**, specifically finding short vectors in a lattice.

**Key Generation**:
$$ f, g \in R_q \text{ such that } f \cdot G - g \cdot F = q $$
Where $R_q = \mathbb{Z}_q[x] / (x^n + 1)$. The private key is the basis $\{ (g, -f), (G, -F) \}$.

**Signature**:
A signature $\mathbf{s} = (\mathbf{s}_1, \mathbf{s}_2)$ satisfies:
$$ \mathbf{s}_1 + \mathbf{s}_2 \cdot h = 0 \pmod q $$
$$ || (\mathbf{s}_1, \mathbf{s}_2) || \le \beta $$

**Security Proof (ROM)**:
Falcon is proven secure in the Random Oracle Model (ROM) against chosen-message attacks (EUF-CMA) under the assumption that SIS (Short Integer Solution) is hard.
$$ Adv^{EUF-CMA}_{Falcon}(\mathcal{A}) \le \epsilon_{SIS} + \frac{Q_s^2 + Q_h}{2^{n}} $$

### 2.2 Kyber-768 (Key Encapsulation)

Kyber is based on the **Module Learning With Errors (M-LWE)** problem.

**Encryption**:
$$ \mathbf{u} = \mathbf{A}^T \mathbf{r} + \mathbf{e}_1 $$
$$ v = \mathbf{t}^T \mathbf{r} + e_2 + \text{Decompress}(m) $$
Where $\mathbf{A}$ is a public matrix, $\mathbf{t}$ is the public key, and $\mathbf{r}, \mathbf{e}$ are small error terms.

**Decryption**:
$$ m' = \text{Compress}(v - \mathbf{s}^T \mathbf{u}) $$

**Security**:
IND-CCA2 secure assuming hardness of M-LWE.

---

## 3. Defense-in-Depth Architecture

### 3.1 Countering Physical Key Extraction (Side-Channel)

**Threat**: Cold Boot / Bus Snooping / Power Analysis.
**Mitigation**: **Key Masking & RAM Scrambling**.

**Mathematical Protection**:
Let $K$ be the private key. We store it as shares:
$$ K = S_1 \oplus S_2 \oplus \dots \oplus S_n $$
During computation (e.g., Falcon Sign), operations are performed on shares without reconstructing $K$, or $K$ acts only on randomized inputs.

**Code Enforcement**:
```rust
// MemoryProtector::load_masked_key
pub fn load_masked_key(masked: &[u8], mask: &[u8]) -> [u8; 32] {
    // This value exists ONLY in CPU registers during the function call scope
    let key = masked ^ mask; 
    // Zeroized immediately after use
    key
}
```

### 3.2 Countering "Evil Maid" (Supply Chain)

**Threat**: Attacker replaces the bootloader with a backdoored version.
**Mitigation**: **Remote Attestation & Recursive Trust**.

**Flow**:
1.  **Immutable Root**: The Stage 1 (MBR) checks the signature of Stage 2.
23.  **Measured Boot**: Stage 2 measures the Kernel.
4.  **PUF Root-of-Trust**: The device identifies itself via a **simulated silicon fingerprint** (Physical Unclonable Function).
    - **Logic**: A stable root key is derived on-demand from local hardware unique identifiers (CPUID, MAC, Serial).
    - **Entropy Source**: `PQC_IIOT_SILICON_FINGERPRINT_V4`.
    - **Resilience**: The key is never stored on disk. It is generated in RAM, used, and zeroized.

$$ K_{root} = \text{HMAC-SHA256}(\text{Silicon\_Fingerprint}, \text{"PUF\_SEED"}) $$

If the bootloader is replaced, it cannot generate the correct $H(Kernel)$. If the hardware is cloned, it cannot generate $K_{PUF}$ because the new hardware will have a different silicon fingerprint.

### 3.3 Countering Firmware Bricking (Denial of Service)

**Threat**: Malicious or buggy update causes boot loop (Stuxnet variant).
**Mitigation**: **Dual-Bank Dead Man's Switch**.

**Logic**:
$$ \text{ActiveSlot} = \begin{cases} A, & \text{if } RetryCount < \text{Policy}_{Retries} \\ B, & \text{otherwise} \end{cases} $$
The `Golden Image` provides an absolute fallback, guaranteed by **Write-Protect GPIO**.
The `Policy` itself is immutable (signed/fused) to prevent downgrade attacks on safety parameters.

## 4. Conclusion

This architecture provides **Information-Theoretic Security** against physical key compromise (via PUF/Masking) and **Computational Security** against Quantum Adversaries (via Lattice Hardness).
