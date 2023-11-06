use std::sync::Once;

use log::LevelFilter;
use log::Log;
use log::Metadata;
use log::Record;

struct StderrLogger;

impl Log for StderrLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        eprintln!("rustssm [{}] {}", record.level(), record.args());
    }

    fn flush(&self) {}
}

static LOGGER: StderrLogger = StderrLogger;

/// Enables logging to stderr when the `RUSTSSM_LOG` environment variable is
/// set (`error`, `warn`, `info`, `debug` or `trace`). A host application that
/// installed its own `log` implementation wins; this is a no-op then.
pub fn init() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let Ok(level) = std::env::var("RUSTSSM_LOG") else {
            return;
        };

        let level = match level.to_lowercase().as_str() {
            "off" => LevelFilter::Off,
            "error" => LevelFilter::Error,
            "warn" => LevelFilter::Warn,
            "info" => LevelFilter::Info,
            "trace" => LevelFilter::Trace,
            _ => LevelFilter::Debug,
        };

        if log::set_logger(&LOGGER).is_ok() {
            log::set_max_level(level);
        }
    });
}
