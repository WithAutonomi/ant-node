//! Logging facade that compiles to no-ops when the `logging` feature is disabled.
//!
//! When the `logging` feature is enabled, this module re-exports the
//! [`tracing`] macros (`info!`, `warn!`, `debug!`, `error!`, `trace!`).
//!
//! When disabled, all macros expand to `()` — zero binary size overhead,
//! zero runtime cost. Argument expressions are **not evaluated**, so
//! `info!("{}", expensive_call())` costs nothing in release builds.
//!
//! ## Unused variables with `--no-default-features`
//!
//! Variables that exist only for logging (e.g. `let addr_hex = hex::encode(...)`)
//! become unused when macros are compiled out. The crate-level attribute
//! `#![cfg_attr(not(feature = "logging"), allow(unused_variables, unused_assignments))]`
//! in `lib.rs` (and the binary entry points) suppresses these expected warnings.

// ---- Feature enabled: re-export tracing ----
#[cfg(feature = "logging")]
pub use tracing::{debug, enabled, error, info, trace, warn, Level};

// ---- Feature disabled: no-op macros ----
//
// `#[macro_export]` places macros at the crate root. We use prefixed names
// to avoid clashing with built-in attributes (e.g. `warn`), then re-export
// them here under the expected names.

#[cfg(not(feature = "logging"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __log_noop_info {
    ($($arg:tt)*) => {
        ()
    };
}

#[cfg(not(feature = "logging"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __log_noop_warn {
    ($($arg:tt)*) => {
        ()
    };
}

#[cfg(not(feature = "logging"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __log_noop_debug {
    ($($arg:tt)*) => {
        ()
    };
}

#[cfg(not(feature = "logging"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __log_noop_error {
    ($($arg:tt)*) => {
        ()
    };
}

#[cfg(not(feature = "logging"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __log_noop_trace {
    ($($arg:tt)*) => {
        ()
    };
}

#[cfg(not(feature = "logging"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __log_noop_enabled {
    ($($arg:tt)*) => {
        false
    };
}

// Re-export under short names so `use crate::logging::info;` works.
#[cfg(not(feature = "logging"))]
pub use __log_noop_debug as debug;
#[cfg(not(feature = "logging"))]
pub use __log_noop_enabled as enabled;
#[cfg(not(feature = "logging"))]
pub use __log_noop_error as error;
#[cfg(not(feature = "logging"))]
pub use __log_noop_info as info;
#[cfg(not(feature = "logging"))]
pub use __log_noop_trace as trace;
#[cfg(not(feature = "logging"))]
pub use __log_noop_warn as warn;

/// Stub for `tracing::Level` when logging is disabled.
#[cfg(not(feature = "logging"))]
#[allow(dead_code)]
pub struct Level;

#[cfg(not(feature = "logging"))]
#[allow(dead_code)]
impl Level {
    /// Debug level stub.
    pub const DEBUG: Self = Self;
    /// Info level stub.
    pub const INFO: Self = Self;
    /// Warn level stub.
    pub const WARN: Self = Self;
    /// Error level stub.
    pub const ERROR: Self = Self;
    /// Trace level stub.
    pub const TRACE: Self = Self;
}

// ---- Build-info stamp for JSON logs ----

/// JSON tail spliced onto every event: `,"node_version":"…","node_commit":"…"}`.
///
/// Both values are compile-time constants of the binary writing the line, so
/// after an auto-upgrade restart the new process stamps its own version with
/// no runtime state involved. Neither value can contain a quote or backslash
/// (Cargo validates the version as semver; the commit is `git rev-parse
/// --short` or the literal `unknown`), so no escaping is needed.
#[cfg(feature = "logging")]
const BUILD_INFO_TAIL: &str = concat!(
    ",\"node_version\":\"",
    env!("CARGO_PKG_VERSION"),
    "\",\"node_commit\":\"",
    env!("ANT_GIT_COMMIT"),
    "\"}"
);

/// Event formatter that stamps `node_version` and `node_commit` onto every
/// JSON log line produced by the wrapped formatter.
///
/// Telemetry needs the running build on *every* document, not just the
/// startup line: a staged rollout is only readable if each log line can be
/// attributed to the build that wrote it. `tracing_subscriber`'s JSON
/// formatter has no hook for constant fields and span fields do not survive
/// `tokio::spawn`, so this wraps the formatter instead: the inner output is
/// rendered into a thread-local buffer, its closing brace is replaced with
/// `BUILD_INFO_TAIL`, and the result is copied to the real writer. Cost is
/// one memcpy per line on top of the serialisation the inner formatter
/// already does.
///
/// Only meaningful around a JSON formatter. If the inner output does not end
/// in `}` it is passed through untouched rather than corrupted.
#[cfg(feature = "logging")]
pub struct WithBuildInfo<F>(pub F);

#[cfg(feature = "logging")]
impl<S, N, F> tracing_subscriber::fmt::FormatEvent<S, N> for WithBuildInfo<F>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> tracing_subscriber::fmt::FormatFields<'a> + 'static,
    F: tracing_subscriber::fmt::FormatEvent<S, N>,
{
    fn format_event(
        &self,
        ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        use std::cell::RefCell;
        use tracing_subscriber::fmt::format::Writer;

        thread_local! {
            static BUF: RefCell<String> = const { RefCell::new(String::new()) };
        }

        let render = |buf: &mut String| -> std::fmt::Result {
            buf.clear();
            self.0.format_event(ctx, Writer::new(buf), event)
        };

        // Re-entrancy (an event emitted while formatting an event) would find
        // the buffer already borrowed; fall back to a fresh allocation for that
        // one line rather than panic.
        let stamped = BUF.with(|cell| {
            let mut buf = cell.try_borrow_mut().ok()?;
            Some(render(&mut buf).and_then(|()| stamp_build_info(&mut writer, &buf)))
        });
        if let Some(result) = stamped {
            return result;
        }
        let mut buf = String::new();
        render(&mut buf)?;
        stamp_build_info(&mut writer, &buf)
    }
}

/// Copy `rendered` to `writer`, replacing its closing brace with
/// [`BUILD_INFO_TAIL`]. Output that is not a JSON object is copied verbatim.
#[cfg(feature = "logging")]
fn stamp_build_info(
    writer: &mut tracing_subscriber::fmt::format::Writer<'_>,
    rendered: &str,
) -> std::fmt::Result {
    let body = rendered.trim_end();
    let Some(open) = body.strip_suffix('}') else {
        return writer.write_str(rendered);
    };
    // An empty object needs no leading comma before the first field.
    let tail = if open.ends_with('{') {
        &BUILD_INFO_TAIL[1..]
    } else {
        BUILD_INFO_TAIL
    };
    writer.write_str(open)?;
    writer.write_str(tail)?;
    writer.write_char('\n')
}

#[cfg(all(test, feature = "logging"))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::WithBuildInfo;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt;
    use tracing_subscriber::fmt::writer::{MakeWriter, MutexGuardWriter};
    use tracing_subscriber::prelude::*;

    /// Shared in-memory sink so the test can read back what the layer wrote.
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for Sink {
        type Writer = MutexGuardWriter<'a, Vec<u8>>;

        fn make_writer(&'a self) -> Self::Writer {
            self.0.make_writer()
        }
    }

    /// Run `emit` under a JSON subscriber wrapped in `WithBuildInfo` and
    /// return the captured lines parsed as JSON objects.
    fn capture(
        with_current_span: bool,
        emit: impl FnOnce(),
    ) -> Vec<serde_json::Map<String, serde_json::Value>> {
        let sink = Sink::default();
        let layer = fmt::layer()
            .json()
            .with_writer(sink.clone())
            .event_format(WithBuildInfo(
                fmt::format()
                    .json()
                    .flatten_event(true)
                    .with_current_span(with_current_span),
            ));
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, emit);

        let bytes = sink.0.lock().expect("sink poisoned").clone();
        let text = String::from_utf8(bytes).expect("log output is not UTF-8");
        text.lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .unwrap_or_else(|e| panic!("line is not valid JSON ({e}): {line}"))
                    .as_object()
                    .cloned()
                    .unwrap_or_else(|| panic!("line is not a JSON object: {line}"))
            })
            .collect()
    }

    fn assert_stamped(doc: &serde_json::Map<String, serde_json::Value>) {
        assert_eq!(
            doc.get("node_version").and_then(|v| v.as_str()),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(
            doc.get("node_commit").and_then(|v| v.as_str()),
            Some(env!("ANT_GIT_COMMIT"))
        );
    }

    #[test]
    fn stamps_every_line_and_keeps_existing_fields() {
        let docs = capture(false, || {
            tracing::info!(peer = "12D3KooW", count = 3, "first");
            tracing::warn!("second");
        });
        assert_eq!(docs.len(), 2, "one JSON line per event");

        assert_stamped(&docs[0]);
        assert_eq!(docs[0]["message"], "first");
        assert_eq!(docs[0]["level"], "INFO");
        assert_eq!(docs[0]["peer"], "12D3KooW");
        assert_eq!(docs[0]["count"], 3);
        assert!(docs[0].contains_key("timestamp"));
        assert!(docs[0].contains_key("target"));

        assert_stamped(&docs[1]);
        assert_eq!(docs[1]["message"], "second");
        assert_eq!(docs[1]["level"], "WARN");
    }

    #[test]
    fn stamps_when_the_last_inner_entry_is_a_nested_object() {
        // With `with_current_span`, the JSON formatter ends the object with a
        // nested `"span":{...}` entry, so the splice must land after the
        // outer brace, not the inner one.
        let docs = capture(true, || {
            let span = tracing::info_span!("handler", request = 7);
            let _guard = span.enter();
            tracing::info!("inside span");
        });
        assert_eq!(docs.len(), 1);
        assert_stamped(&docs[0]);
        assert_eq!(docs[0]["span"]["name"], "handler");
        assert_eq!(docs[0]["span"]["request"], 7);
    }

    #[test]
    fn version_matches_the_crate_version() {
        // The stamp must be the build's own version — the whole point is that
        // a freshly upgraded binary reports itself, not a provisioned string.
        let docs = capture(false, || tracing::info!("v"));
        let stamped = docs[0]["node_version"].as_str().expect("string");
        assert_eq!(stamped, env!("CARGO_PKG_VERSION"));
        assert!(
            semver::Version::parse(stamped).is_ok(),
            "node_version should be a semver string: {stamped}"
        );
    }
}
