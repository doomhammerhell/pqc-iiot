# Deep IIoT Scenarios: Use Cases for "Abyssal" Security

This document outlines deployment scenarios for **PQC-Boot** in critical infrastructure, where failure or compromise leads to catastrophic physical consequences.

## Case Study 1: The Nuclear Reactor Failsafe Controller

**Environment**: Primary Cooling Loop Control Unit (PLCU).
**Threat Model**: Nation-State actor attempting to inject malicious firmware to disable cooling pumps (Stuxnet-style).
**Constraint**: System is air-gapped but updates are delivered via technicians with toughbooks (potential vector). Physical access is restricted but not impossible for insiders.

### The "Dead Man's Switch" Configuration

To prevent a bad update (or a malicious one that wipes the system) from causing a meltdown, the controller uses the **Dual-Bank A/B with Dead Man's Switch**.

#### Configuration (`src/lib.rs` snippet)

```rust
// HARDWARE_CONFIG: PLCU_V2 (Policy-Driven)
pub struct SecurityPolicy {
    pub max_retries: u8,
    pub watchdog_timeout_ms: u32,
}

// this would be burnt into eFuses or signed config partition
pub const POLICY: SecurityPolicy = SecurityPolicy {
    max_retries: 3,              // Configurable resilience
    watchdog_timeout_ms: 300_000 // 5 minutes
};

pub const PARTITION_LAYOUT: PartitionTable = PartitionTable {
    slot_a: Partition { start_lba: 2048, size: 32768, active: true, retry_count: 0 },
    slot_b: Partition { start_lba: 34816, size: 32768, active: false, retry_count: 0 },
    golden: Partition { start_lba: 67584, size: 8192, active: true, retry_count: 0 },
};
```

#### The Logic Flow

1.  **Update**: Technician uploads standard signed firmware to `Slot A`.
2.  **Boot**: PQC-Boot verifies Falcon-512 signature. **Result: Valid**.
3.  **Execution**: Kernel loads, but contains a subtle logic bomb that hangs the cooling control loop.
4.  **Reaction**:
    - The OS Watchdog driver fails to "pet" the hardware watchdog because the thread is hung.
    - **T+300s**: Hardware Watchdog resets the CPU.
    - **Reboot 1**: PQC-Boot sees `nvram_counter == 1`. Trie Slot A again.
    - ...
    - **Reboot 3**: PQC-Boot sees `nvram_counter >= POLICY.max_retries` (3).
    - **Action**: `PartitionManager` swaps Active Slot to `Slot B` (Previous Known Good).
    - **Result**: Reactor cooling control is restored automatically.

**Abyssal Feature**: The `Golden Image` provides a tertiary fallback that is physically write-protected (GPIO pin grounded), meaning no software can overwrite it.

---

## Case Study 2: The Subsea Cable Repeater (Anti-Tamper)

**Environment**: Optical Amplifier located 4,000m deep.
**Threat Model**: Sophisticated adversary retrieving the physical device (via submarine) to extract private keys for Man-in-the-Middle traffic decryption.
**Constraint**: Physical access is possible by the adversary. Cold Boot attacks are feasible if the device is brought to the surface quickly.

### Memory Obfuscation & Key Masking

To prevent key extraction from RAM, PQC-Boot employs **Anti-Tamper Memory Protection**.

#### Memory Scrambling (`src/lib.rs` logic)

Before any sensitive material is loaded, the RAM is actively erased with high-entropy patterns.

```rust
// BootVerifier::verify_boot_flow
pub fn verify_boot_flow(...) {
    // 1. Anti-Tamper: Scramble RAM
    // Writes pseudo-random noise to 100% of available DRAM
    // prevents "data burn-in" or remnance from previous sessions.
    MemoryProtector::scramble_ram(DRAM_START, DRAM_SIZE);
    
    // ... Load Kernel ...
}
```

#### Key Masking (Split-Key Storage)

The Device Identity Key (Falcon Private Key) is NOT stored in plain text in the SPI Flash or RAM.

$$ K_{real} = K_{partA} \oplus K_{partB} $$

- **Part A**: Stored in SPI Flash (Encrypted).
- **Part B**: Derived from Physical Unclonable Function (PUF) characteristic of the silicon.

```rust
// Crypto Core Logic
pub fn reconstruct_key_and_sign(msg: &[u8]) -> Signature {
    // 1. Read Encrypted Part A
    let k_a = flash.read(KEY_ADDR);
    
    // 2. Derive Part B from Silicon PUF
    let k_b = puf.read_challenge(CHALLENGE_STATIC);
    
    // 3. Reconstruct in Registers ONLY (No RAM Write)
    let k_real = k_a ^ k_b;
    
    // 4. Sign
    let sig = falcon_sign(k_real, msg);
    
    // 5. Zeroize Registers
    zeroize(k_real);
    
    sig
}
```

**Abyssal Result**: Even if the attacker dumps the Flash and dumps the RAM (Cold Boot), they only get `Key_A` and random noise. Without the specific physics of that exact silicon chip (`Key_B`), the private key is mathematically irrecoverable.

---

## Case Study 3: The Smart Grid Substation (Remote Attestation)

**Environment**: Electrical Grid Distribution Node.
**Threat Model**: Insider threat replaces the bootloader with a "Evil Maid" version that bypasses checks but reports "OK" to the central server.

### Universal Remote Attestation

The Central SCADA Controller refuses to send the "Grid Connect" command unless the device proves its boot state.

#### The Protocol

1.  **Challenge**: Server sends `Nonce_S` (Random 16 bytes).
2.  **Execution**:
    - PQC-Boot calculates `H_kernel = SHA256(Kernel_Memory)`.
    - PQC-Boot calculates `H_bios = SHA256(BIOS_ROM)`.
    - PQC-Boot derives `K_ephemeral` from the boot session.
    - PQC-Boot signs the Quote: `Sig = Falcon_Sign(K_device, H_kernel || H_bios || Nonce_S)`.
3.  **Response**: Device sends `Quote { H_kernel, H_bios, Nonce_S, Sig }`.
4.  **Verification**:
    - Server verifies `Sig` using Device Public Key.
    - Server verifies `Nonce_S` matches what it sent (Anti-Replay).
    - Server verifies `H_kernel` matches the expected firmware hash ("v1.0.4").

**Code Snippet (`pqc-boot/core/src/lib.rs`)**:

```rust
pub fn verify_boot_flow(&self, nonce: &[u8]) -> AttestationReport {
    // ... verify kernel ...
    
    // Generate Binding Quote
    // "I attest that I have just verified Hash(Kernel) 
    //  and I am running on Device(ID) with Nonce(N)"
    let quote = Attestator::generate_quote(&kernel_hash, nonce);
    
    // Only IF the report is valid does the OS get the keys to join the network.
    quote
}
```

**Abyssal Result**: The "Evil Maid" bootloader, lacking the hardware-bound Device Private Key or the correct Kernel Hash, cannot generate a valid signature for the Server's challenge. The grid connection remains denied.
