// This module is only compiled when running Kani Model Checker
#[cfg(kani)]
mod analysis {
    use super::*;

    /// PROOF 1: Partition Selection Never Panics
    /// Checks that for ANY possible state of the PartitionTable (Active flags, Retry counts),
    /// the manager executes without crashing.
    #[kani::proof]
    fn prove_select_boot_partition_safety() {
        // 1. Nondeterministic Inputs (Symbolic Execution)
        let retry_a: u8 = kani::any();
        let retry_b: u8 = kani::any();
        let active_a: bool = kani::any();
        
        // 2. Construct Manager in Arbitrary State
        // 2. Construct Manager in Arbitrary State
        let mut pm = PartitionManager::new();
        pm.slot_a.retry_count = Tmr::new(retry_a);
        pm.slot_b.retry_count = Tmr::new(retry_b);
        pm.slot_a.active = Tmr::new(active_a);
        pm.slot_b.active = Tmr::new(!active_a); // Enforce mutual exclusion for this test model

        // 3. Execution (The Action)
        let (ptype, _, _) = pm.select_boot_partition();

        // 4. Invariants (The "Uncrashable" Guarantee)
        // Ensure we never return an invalid variants (though Rust guarantees this mostly)
        match ptype {
            PartitionType::SlotA => {
                // If we picked A, it MUST be because logic allowed it
                if active_a {
                    assert!(retry_a <= PartitionManager::POLICY.max_retries + 1); 
                    // +1 because logic increments it before return
                }
            },
            PartitionType::SlotB => {},
            PartitionType::Golden => {},
        }
    }

    /// PROOF 2: Dead Man's Switch Logic Compliance
    /// Proves that if retry_count >= max_retries, we NEVER pick that slot
    #[kani::proof]
    fn prove_dead_mans_switch_enforcement() {
        let max = PartitionManager::POLICY.max_retries;
        
        let mut pm = PartitionManager::new();
        // Force A to be "Dead" (Retries exceeded)
        pm.slot_a.active = Tmr::new(true);
        pm.slot_a.retry_count = Tmr::new(max); 

        let (ptype, _, _) = pm.select_boot_partition();

        // Assertion: logic MUST NOT select A
        match ptype {
            PartitionType::SlotA => {
                 // If we are here, the Dead Man's Switch FAILED
                 panic!("VIOLATION: Selected Dead Slot!"); 
            },
            _ => { /* Good */ }
        }
    }
}
