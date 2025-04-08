use clap::{Parser, ValueEnum};
use log::LevelFilter;

/// Enum representing different verbosity levels.
#[derive(ValueEnum, Clone, Debug)]
enum Verbosity {
    /// No logs will be shown.
    None,

    /// Trace level logs.
    Trace,

    /// Debug level logs.
    Debug,

    /// Info level logs (default).
    Info,

    /// Warn level logs.
    Warn,

    /// Error level logs.
    Error,
}

#[derive(Parser, Debug)]
pub struct AppConfig {
    /// TCP/UDP Listening Port
    #[clap(short, long, default_value = "8080")]
    port: String,

    #[clap(long, use_value_delimiter = true, value_delimiter = ',')]
    initial_peers: Vec<String>,

    /// Enable or disable vertex auto-generator
    #[clap(long, default_value_t = false)]
    auto_generate_vertices: bool,

    /// Set the verbosity level
    #[clap(
        long,
        value_enum,
        default_value = "info",
        help = "Set the verbosity level"
    )]
    verbosity: Verbosity,
}

impl AppConfig {
    pub fn get_auto_generate_vertices(&self) -> bool {
        self.auto_generate_vertices
    }

    pub fn get_config_port(&self) -> String {
        self.port.clone()
    }

    pub fn get_initial_peers(&self) -> Vec<String> {
        self.initial_peers.clone()
    }

    // Set up logging based on verbosity
    pub fn setup_logging(&self) {
        let level_filter = match self.verbosity {
            Verbosity::None => LevelFilter::Off,
            Verbosity::Trace => LevelFilter::Trace,
            Verbosity::Debug => LevelFilter::Debug,
            Verbosity::Info => LevelFilter::Info,
            Verbosity::Warn => LevelFilter::Warn,
            Verbosity::Error => LevelFilter::Error,
        };

        // Initialize the logger with the chosen level
        env_logger::builder().filter_level(level_filter).init();
    }
}
