//! Platform-specific process configuration.
//!
//! On macOS, prevents App Nap from throttling the node process. macOS
//! aggressively suspends background processes that have no visible UI,
//! coalescing timers and reducing CPU priority. This makes scheduled
//! operations (like upgrade checks) unreliable — timers can be deferred
//! by minutes or even tens of minutes.

/// Opaque handle representing an active App Nap prevention activity.
/// The activity remains active as long as this value is alive.
#[cfg(target_os = "macos")]
pub type AppNapActivity = objc2::rc::Retained<objc2::runtime::NSObject>;

/// Prevent macOS App Nap from throttling this process.
///
/// Calls `NSProcessInfo.processInfo.beginActivity(_:reason:)` with
/// `NSActivityUserInitiated` to tell macOS this process is performing
/// important work that should not be deferred.
///
/// The returned handle must be held for the lifetime of the process.
/// When dropped, macOS may resume App Nap.
///
/// # Errors
///
/// Returns an error string if the activity could not be created.
#[cfg(target_os = "macos")]
pub fn disable_app_nap() -> Result<AppNapActivity, String> {
    #[allow(unsafe_code)]
    // SAFETY: We call well-documented Cocoa APIs through the objc2 safe
    // wrappers. `processInfo` returns a shared singleton and
    // `beginActivityWithOptions:reason:` is thread-safe.
    unsafe {
        use objc2::msg_send_id;
        use objc2_foundation::{NSProcessInfo, NSString};

        let process_info = NSProcessInfo::processInfo();

        // NSActivityUserInitiated (0x00FFFFFFU) includes latency-critical
        // timer firing, App Nap prevention, and idle sleep prevention.
        let options: u64 = 0x00FF_FFFF;

        let reason =
            NSString::from_str("saorsa-node: P2P network daemon performing background operations");

        let activity: AppNapActivity = msg_send_id![
            &process_info,
            beginActivityWithOptions: options,
            reason: &*reason,
        ];

        Ok(activity)
    }
}

/// No-op on non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn disable_app_nap() -> Result<(), String> {
    Ok(())
}
