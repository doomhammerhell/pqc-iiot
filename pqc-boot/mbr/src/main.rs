#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};
use pqc_boot_core::{BootVerifier, Platform, Error};

// --- Global Allocator (Bump Pointer) ---
struct BumpAllocator {
    head: AtomicUsize,
    end: usize,
}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator {
    head: AtomicUsize::new(0x200000), // Start Heap at 2MB
    end: 0x400000,                    // End Heap at 4MB
};

unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();
        
        let mut head = self.head.load(Ordering::Relaxed);
        // Align
        let remainder = head % align;
        if remainder != 0 {
            head += align - remainder;
        }

        let new_head = head + size;
        if new_head > self.end {
            core::ptr::null_mut() // OOM
        } else {
            self.head.store(new_head, Ordering::Relaxed);
            head as *mut u8
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // Bump allocator leaks everything. Accepted for bootloader Stage 2.
    }
}

// --- Platform Implementation ---
struct BiosPlatform;

impl BiosPlatform {
    unsafe fn outb(port: u16, val: u8) {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
    }

    unsafe fn inb(port: u16) -> u8 {
        let ret: u8;
        core::arch::asm!("in al, dx", out("al") ret, in("dx") port, options(nomem, nostack));
        ret
    }
    
    unsafe fn insw(port: u16, buf: &mut [u16]) {
         for x in buf {
             core::arch::asm!("in ax, dx", out("ax") *x, in("dx") port, options(nomem, nostack));
         }
    }
}

impl Platform for BiosPlatform {
    fn console_print(&self, msg: &str) {
        // Write to VGA Buffer 0xB8000
        static mut CURSOR: usize = 0;
        let vga_buffer = 0xB8000 as *mut u8;
        
        for byte in msg.bytes() {
            unsafe {
                if CURSOR >= 80 * 25 * 2 { CURSOR = 0; }
                
                if byte == b'\n' {
                    CURSOR += 160 - (CURSOR % 160);
                } else {
                    *vga_buffer.add(CURSOR) = byte;
                    *vga_buffer.add(CURSOR + 1) = 0x0F; // White on Black
                    CURSOR += 2;
                }
            }
        }
    }

    fn read_disk(&self, lba: u64, buffer: &mut [u8]) -> Result<(), Error> {
        // ATA PIO Mode LBA28 (Simplified)
        // Assume Primary Bus, Master Drive (Ports 0x1F0-0x1F7)
        
        let lba = lba as u32; // Limit to 32-bit LBA for MBR
        let sector_count = (buffer.len() / 512) as u8;
        
        if sector_count == 0 { return Ok(()); }
        
        unsafe {
            // Select Drive (Master, LBA mode) | Top 4 bits of LBA
            BiosPlatform::outb(0x1F6, 0xE0 | ((lba >> 24) as u8 & 0x0F));
            
            // Send NULL to Error Register
            BiosPlatform::outb(0x1F1, 0x00);
            
            // Sector Count
            BiosPlatform::outb(0x1F2, sector_count);
            
            // LBA Low
            BiosPlatform::outb(0x1F3, lba as u8);
            
            // LBA Mid
            BiosPlatform::outb(0x1F4, (lba >> 8) as u8);
            
            // LBA High
            BiosPlatform::outb(0x1F5, (lba >> 16) as u8);
            
            // Command: READ SECTORS (0x20)
            BiosPlatform::outb(0x1F7, 0x20);

            // Poll for DRQ
            for _ in 0..sector_count {
                loop {
                    let status = BiosPlatform::inb(0x1F7);
                    if status & 0x08 != 0 { break; } // DRQ set
                    if status & 0x01 != 0 { return Err(Error::DiskError); } // ERR set
                }
                
                // Read 256 words (512 bytes)
                for i in 0..256 {
                    let word: u16;
                    core::arch::asm!("in ax, dx", out("ax") word, in("dx") 0x1F0_u16, options(nomem, nostack));
                    
                    // Buffer is u8, we need to write two bytes
                    // Careful with buffer bounds!
                    let idx = i * 2;
                    if idx + 1 < buffer.len() {
                         buffer[idx] = (word & 0xFF) as u8;
                         buffer[idx + 1] = (word >> 8) as u8;
                    }
                }
            }
        }
        
        Ok(())
    }

    fn get_random_bytes(&self, buffer: &mut [u8]) -> Result<(), Error> {
        // Jitter Entropy: Read RDTSC
        let mut seed = unsafe { core::arch::x86::match_rdtsc() }; // Simplified intrinsic name
        // Actually need core::arch::x86::_rdtsc() if available or asm
        
         let tsc_lo: u32;
         let tsc_hi: u32;
         unsafe {
             core::arch::asm!("rdtsc", out("eax") tsc_lo, out("edx") tsc_hi, options(nomem, nostack));
         }
         let tsc = ((tsc_hi as u64) << 32) | (tsc_lo as u64);
         
         for byte in buffer {
             *byte = (tsc & 0xFF) as u8;
             // Rotate
             // ...
         }
        Ok(())
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let platform = BiosPlatform;
    platform.console_print("PQC-Boot BIOS Loaded.\n");
    
    let verifier = BootVerifier::new(&platform);
    
    // Check Kernel
    // REAL IMPLEMENTATION: Read Sector 1 (512 bytes) + Sector 2 (partial) for signature
    // Falcon-512 signature is ~666 bytes. Round up to 2 sectors (1024 bytes).
    let mut sig_buffer = [0u8; 1024];
    if let Err(_) = platform.read_disk(1, &mut sig_buffer) {
        platform.console_print("BOOT ERROR: Disk Read Failed\n");
        loop {}
    }

    // Verify
    match verifier.verify_boot_flow(&sig_buffer[..730]) {
        Ok((true, _)) => platform.console_print("Kernel Verified! (Booting...)\n"),
        Ok((false, _)) => {
            platform.console_print("BOOT FAILED: Signature Invalid!\n");
            loop {} // Halt
        }
        Err(_) => {
            platform.console_print("BOOT FAILED: Error!\n");
            loop {} // Halt
        }
    }

    loop {}
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let platform = BiosPlatform;
    platform.console_print("PANIC!\n");
    loop {}
}
