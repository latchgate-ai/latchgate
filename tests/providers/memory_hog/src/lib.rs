//! Adversarial WASM fixture: allocates memory aggressively until the wasmtime
//! StoreLimits memory cap fires and traps the module.
//!
//! Used exclusively in `memory_limit_terminates_memory_hog_provider` to prove
//! that `ResourceLimits::memory_mb` actually bounds linear memory growth.
//! Never deploy as a real action provider.

wit_bindgen::generate!({
    world: "provider",
    path: "../../../providers/wit",
});

struct Provider;
export!(Provider);

impl Guest for Provider {
    fn execute(_task_json: String) -> Result<String, String> {
        // Allocate in 1 MiB chunks, keeping every chunk alive so the
        // allocator cannot reclaim memory between iterations.
        // wasmtime StoreLimits traps once linear memory exceeds the cap.
        let mut kept: Vec<Vec<u8>> = Vec::new();
        loop {
            let chunk = vec![0xABu8; 1024 * 1024];
            kept.push(chunk);
            // Touch last element to prevent dead-store elimination.
            let _ = kept.last().map(|v| v[0]);
        }
    }
}
