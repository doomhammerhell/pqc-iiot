# Security Proofs & Reductions

## Kyber: Indistinguishability under Chosen Ciphertext Attack (IND-CCA2)

Kyber is constructed using the **Fujisaki-Okamoto (FO)** transform on an IND-CPA secure encryption scheme (Kyber.CPAPKE).

### Hardness Assumption: Module-LWE
The security of Kyber reduces to the hardness of the Module-LWE problem.

**Theorem (Informal)**: If the Module-LWE problem is hard for the parameters $(n, k, q, \eta)$, then Kyber.CPAPKE is IND-CPA secure.

### The FO Transform
To achieve IND-CCA2 security (active security against attackers who can decrypt chosen ciphertexts), Kyber applies a variant of the Fujisaki-Okamoto transform:

1.  **Encryption**: $c = \text{Kyber.CPAPKE.Enc}(pk, m; G(m, pk))$
2.  **Decryption**:
    - Recover $m'$ from $c$.
    - Re-encrypt $m'$ to get $c'$.
    - If $c \neq c'$, output $\perp$ (failure). This implicit rejection prevents malleability attacks.

This reduction is tight in the Random Oracle Model (ROM).

## Falcon: Existential Unforgeability under Chosen Message Attack (EUF-CMA)

Falcon's security is based on the **NTRU** problem and the **Short Integer Solution (SIS)** problem.

### Hardness Assumption: SIS over NTRU Lattices
Finding a signature is equivalent to solving a specific instance of the closest vector problem (CVP) on the NTRU lattice.

**Theorem (Informal)**: In the Random Oracle Model (ROM), Falcon is EUF-CMA secure assuming the hardness of the SIS problem over NTRU lattices.

### Side-Channel Resistance
The implementation of the trapdoor sampler (Gaussian sampling) must be constant-time to prevent timing attacks (e.g., simple power analysis or cache-timing). Falcon uses a specific constant-time Gaussian sampler to ensure that the time taken to sign is independent of the secret key and the signature value.

## Hybrid Security Model

PQC-IIoT operates in a hybrid mode (Classical + Post-Quantum) for encryption (AES-256 + Kyber).

### Combiner Security
Let $K_{Class}$ be the key derived from classical exchange (e.g., ECDH, though PQC-IIoT currently focuses on PQ-only KEM for simplicity in Version 1, the architecture allows mixing).

For the KEM + Authenticated Encryption (Kyber + AES-GCM):
Security depends on:
1.  **Kyber (IND-CCA2)**: Ensures the shared secret for AES key derivation is secure against quantum adversaries.
2.  **AES-GCM (IND-CCA2 / INT-CTXT)**: Ensures confidentiality and integrity of the payload given a secure key.

If *either* the KEM key exchange is broken OR the AES-GCM encryption is broken, the system is compromised. However, since AES-256 is considered quantum-resistant (Grover's algorithm only halves the key space to 128 bits), the combination provides robust long-term security.
