# Mathematical Foundations

## Lattice-Based Cryptography Primer

PQC-IIoT relies on the hardness of finding short vectors in high-dimensional lattices. Specifically, we utilize two variants of the Learning With Errors (LWE) problem:

1.  **Module-LWE (MLWE)**: Used by **Kyber**.
2.  **NTRU Lattices**: Used by **Falcon**.

### The Learning With Errors (LWE) Problem

Given a matrix $A \in \mathbb{Z}_q^{m \times n}$ and a vector $b = As + e$, where $s$ is a secret vector and $e$ is a small error vector, the LWE problem asks to recover $s$. The security relies on the fact that without $s$, $b$ is indistinguishable from a uniformly random vector.

### Module-LWE (MLWE)

MLWE is a structured variant where elements are polynomials in a ring $R_q = \mathbb{Z}_q[X]/(X^n + 1)$. This structure allows for smaller key sizes and faster operations via the Number Theoretic Transform (NTT).

In Kyber, the public key is a module element $t = As + e$ over the ring $R_q$.

## Kyber-768 Specification (NIST Level 3)

Kyber is a Module-LWE based Key Encapsulation Mechanism (KEM).

### Parameters (Kyber-768)
- **Ring Degree ($n$)**: 256
- **Modulus ($q$)**: 3329 (Chosen because $n | (q-1)$, enabling efficient NTT)
- **Module Rank ($k$)**: 3 (Determines the dimension of the matrix/vectors)
- **Noise Parameter ($\eta_1$)**: 2
- **Noise Parameter ($\eta_2$)**: 2
- **Public Key Size**: $12 \times k \times n / 8 + 32 = 1184$ bytes
- **Secret Key Size**: $12 \times k \times n / 8 + 12 \times k \times n / 8 + 32 + 32 + 32 = 2400$ bytes
- **Ciphertext Size**: $1088$ bytes

### Number Theoretic Transform (NTT)
Kyber uses NTT for efficient polynomial multiplication. The modulus $q=3329$ is a prime number such that $q \equiv 1 \pmod{2n}$. This allows defining a primitive $2n$-th root of unity $\zeta = 17$.

Multiplication in $R_q$ has complexity $O(n \log n)$ instead of $O(n^2)$.

## Falcon-512 Specification (NIST Level 1 / 5)

Falcon is a lattice-based signature scheme based on the Gentry-Peikert-Vaikuntanathan (GPV) framework using NTRU lattices. It employs a "hash-and-sign" paradigm.

### Parameters (Falcon-512)
- **Ring Degree ($n$)**: 512
- **Modulus ($q$)**: 12289
- **Signature Size**: 666 bytes (variable, average)
- **Public Key Size**: 897 bytes

### Trapdoor Sampling
Falcon's security relies on the ability to sample short vectors in a lattice given a "trapdoor" (the secret key). The signing process involves:
1.  Hashing the message to a point $c$ in the lattice.
2.  Using the secret key (trapdoor) to find a lattice vector $v$ close to $c$.
3.  The signature is the difference $s = c - v$, which is a short vector.
4.  Verification checks if $H(m) - s$ is a valid lattice point and if $s$ is sufficiently short.

### Fast Fourier Transform (FFT)
Unlike Kyber's NTT over finite fields, Falcon operations involve arithmetic over complex numbers using standard FFT, requiring floating-point precision management (or emulated fixed-point in `no_std` environments).
