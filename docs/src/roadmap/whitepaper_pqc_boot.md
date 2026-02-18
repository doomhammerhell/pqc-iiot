# Whitepaper: PQC-Boot — A Universal Post-Quantum Secure Bootloader

## Abstract
This whitepaper defines the architecture for **PQC-Boot**, a unified secure bootloader capable of enforcing Post-Quantum Cryptographic (PQC) verification on both modern **UEFI** systems and legacy **BIOS (MBR)** industrial controllers. By implementing a `no_std` Rust core with pluggable platform frontends, PQC-Boot provides a retroactive security path for critical infrastructure that lacks native TPM or Secure Boot hardware capabilities.

## 1. Problem Statement
Industrial IoT (IIoT) environments are heterogeneous. While modern gateways run 64-bit UEFI with TPM 2.0, vast amounts of critical infrastructure operate on legacy 16-bit BIOS architectures (x86) without hardware root-of-trust.
- **Challenge A**: Legacy systems cannot verify modern signatures (RSA-4096 or ECC) due to performance and memory constraints, let alone post-quantum algorithms (Falcon-512).
- **Challenge B**: The transition to PQC requires a unified chain-of-trust that works across this generational divide.

## 2. System Architecture

PQC-Boot utilizes a split-architecture design:
1.  **Boot Core (`pqc-boot-core`)**: Platform-agnostic, `no_std` Rust library containing the Falcon-512 signature verification logic, SHA-256 hashing, and Kyber-768 key encapsulation (for update decryption).
2.  **Platform Abstraction Layer (PAL)**: Traits for Console, Disk I/O, and Memory Allocation.
3.  **Frontends**:
    - `pqc-boot-uefi`: For modern boards (PE32+ executable).
    - `pqc-boot-mbr`: For legacy boards (Stage 1 + Stage 2 raw binary).

### 2.1 The Boot Core (`no_std`)

The core must operate without an Operating System.

```rust
#![no_std]
extern crate alloc;

pub trait Platform {
    fn read_disk(&self, lba: u64, buffer: &mut [u8]) -> Result<(), Error>;
    fn console_log(&self, msg: &str);
    fn get_random_bytes(&self, buffer: &mut [u8]) -> Result<(), Error>; // RDRAND or Jitter
}

pub fn verify_kernel(platform: &impl Platform, kernel_lba: u64, size: usize, signature: &[u8]) -> bool {
    // 1. Load kernel into RAM (chunked)
    // 2. Compute SHA-256 hash
    // 3. Verify Falcon-512 Signature against embedded Root of Trust Checksum
    pqc_falcon::verify(PUBLIC_KEY, hash, signature)
}
```

## 3. Implementation Strategy: UEFI (Modern)

Target: `x86_64-unknown-uefi`

1.  **Entry Point**: Rust `uefi::entry` macro.
2.  **Memory**: Uses UEFI Boot Services `allocate_pool`.
3.  **Entropy**: Calls `EFI_RNG_PROTOCOL`.
4.  **Flow**:
    - PQC-Boot loads as a standard UEFI Application (`/EFI/BOOT/BOOTX64.EFI`).
    - It validates the Linux Kernel (`vmlinuz`) signature stored in the ESP partition.
    - If valid, it uses `LoadImage` / `StartImage` to hand over control.
    - If invalid, it halts or reboots into recovery.

## 4. Implementation Strategy: Legacy BIOS (The "Abyssal" Challenge)

Target: `x86-unknown-none` (Custom Linker Script)

Legacy BIOS starts the CPU in **Real Mode (16-bit)** with only 1MB addressable RAM. Falcon-512 requires significantly more resources and 32/64-bit arithmetic.

### 4.1 Stage 1: The MBR (512 bytes)
- **Role**: Minimal assembly shim.
- **Action**: Copies **Stage 2** from sectors 1-64 of the disk into RAM address `0x7E00`.
- **Constraint**: No crypto here. Just raw block copy via BIOS INT 13h.

### 4.2 Stage 2: The Rust Loader (Protected Mode)
This is the heart of the legacy implementation.
1.  **Mode Switch**: Immediately disable interrupts (`cli`), enable A20 line, load a Global Descriptor Table (GDT), and switch CPU to **32-bit Protected Mode** (or Long Mode).
2.  **Stack Setup**: Set stack pointer to a safe high memory region (e.g., `0x90000`).
3.  **Driver Initialization (PIO)**: Since BIOS interrupts (INT 13h) are gone in Protected Mode, Stage 2 must include a minimal **PIO (Programmed I/O)** driver to read the IDE/SATA disk ports directly or switch back-and-forth to Real Mode (Unreal Mode) using "thunks".
4.  **Verification**:
    - Load the Kernel (bzImage) to `0x100000` (1MB+ mark).
    - Run `pqc-boot-core` verification (Falcon-512).
    - **Floating Point Unit (FPU)**: Enable SSE/AVX registers manually (BIOS leaves them off). Falcon requires FPU.

### 4.3 Entropy Gap
Legacy BIOS has no TRNG.
- **Solution**: Implement a "Jitter Entropy" collector measuring CPU execution time variance of loops against the Real Time Clock (RTC) or Programmable Interval Timer (PIT).
- **Hardening**: Mix this entropy with a stored seed (updated on every successful boot) to prevent boot-time predictability attacks.

## 5. Memory Management (The Allocator)

Both implementations require dynamic memory for Falcon's large signature structs (approx 4-8KB stack + heap).

- **Global Allocator**: We implement `GlobalAlloc` using a simple "Bump Pointer" or "Linked List" allocator over a reserved RAM region (e.g., `0x200000` - `0x400000`).

```rust
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

fn init_heap() {
    let heap_start = 0x200000;
    let heap_size = 1024 * 1024; // 1MB Heap
    unsafe { ALLOCATOR.lock().init(heap_start, heap_size) };
}
```

## 6. Root of Trust & Provisioning

- **Key Storage**: The "Root" Falcon Public Key is compiled directly into the `pqc-boot` binary.
- **Key Rotation**: To rotate the root key, the bootloader binary itself must be updated. This update process is secured by the *current* valid bootloader (Recursive Trust).

## 7. Roadmap to Execution

### Phase 2.1: Prototype UEFI
- Build `pqc-boot-uefi` standard application.
- Validate Kernel signing on QEMU OVMF.

### Phase 2.2: The Core Logic
- Extract `falcon` and `sha2` into a pure `no_std` crate.
- Implement `GlobalAlloc` shim.

### Phase 2.3: Legacy Assembly
- Write the MBR shim (NASM).
- Write the Mode Switch shim (32-bit Protected).
- Link Rust static library to the Assembly shim.

## 8. Conclusion
PQC-Boot allows operators to extend the lifespan of legacy industrial hardware by wrapping them in a Post-Quantum security layer, bypassing the need for physical TPM upgrades. This "Software-defined Root of Trust" is essential for securing the brownfield IIoT landscape against Q-Day.
