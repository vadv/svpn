//! The flow-count ceiling is limited only by OS resources; we raise RLIMIT_NOFILE at startup.

use rlimit::Resource;

pub fn raise_and_report() {
    match Resource::NOFILE.get() {
        Ok((soft, hard)) => {
            // The target is the hard limit; on macOS it can be infinite (RLIM_INFINITY)
            // and the kernel refuses — we stay at the current value.
            let raised = Resource::NOFILE.set(hard, hard).is_ok();
            let effective = Resource::NOFILE.get().map_or(soft, |(now, _)| now);
            crate::debug!(
                "nofile soft={soft} hard={hard} raised={raised} effective_soft={effective}"
            );
        }
        Err(error) => crate::error!("nofile get failed: {error}"),
    }
}
