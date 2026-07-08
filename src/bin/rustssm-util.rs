//! Command-line tool to provision rustssm tokens (initialize tokens, set PINs, import keys) without going through the
//! PKCS#11 API — a roughly similar to `softhsm2-util`.

use std::path::PathBuf;
use std::process::exit;

use clap::Args;
use clap::Parser;
use clap::Subcommand;
use rustssm::admin;
use rustssm::admin::SlotSelector;

#[derive(Parser)]
#[command(name = "rustssm-util", about = "Provision rustssm tokens (softhsm2-util-style)")]
struct Cli {
    /// SQLite store path (default: $RUSTSSM_DATABASE_URL, else rustssm.db).
    /// Must match the path the loaded module uses.
    #[arg(long, global = true)]
    database: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List slots and their token state.
    ShowSlots,

    /// Initialize a token: set its SO PIN, label and optionally the user PIN.
    /// Destroys any objects already in the store.
    InitToken(InitTokenArgs),

    /// Import a raw AES key from a file as a labelled secret-key object.
    Import(ImportArgs),
}

#[derive(Args)]
struct InitTokenArgs {
    /// Token label.
    #[arg(long)]
    label: String,

    /// Security Officer PIN.
    #[arg(long)]
    so_pin: String,

    /// User PIN to set (optional).
    #[arg(long)]
    user_pin: Option<String>,

    #[command(flatten)]
    slot: SlotArg,
}

#[derive(Args)]
struct ImportArgs {
    /// Key type marker; only AES import is supported.
    #[arg(long)]
    aes: bool,

    /// Path to the raw key file (the key bytes verbatim).
    key_file: PathBuf,

    /// Object label.
    #[arg(long)]
    label: String,

    /// Object id (`CKA_ID`), hex-encoded.
    #[arg(long)]
    id: Option<String>,

    /// User PIN (a login is required to create the object).
    #[arg(long)]
    user_pin: String,

    #[command(flatten)]
    target: TargetSlotArg,
}

/// Decodes a hex string into bytes `--id`.
fn parse_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err(String::from("hex value must have an even number of digits"));
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| format!("invalid hex: {value}")))
        .collect()
}

/// Slot selector for `init-token`: exactly one of `--free`, `--slot`, `--token`.
#[derive(Args)]
#[group(required = true, multiple = false)]
struct SlotArg {
    /// Use the first uninitialized slot.
    #[arg(long)]
    free: bool,

    /// Use a specific slot by id.
    #[arg(long)]
    slot: Option<u64>,

    /// Use the slot whose token has this label.
    #[arg(long)]
    token: Option<String>,
}

impl SlotArg {
    fn selector(self) -> SlotSelector {
        if let Some(id) = self.slot {
            SlotSelector::Slot(id)
        } else if let Some(label) = self.token {
            SlotSelector::Token(label)
        } else {
            // clap guarantees exactly one of the group is set.
            SlotSelector::Free
        }
    }
}

/// Slot selector for `import`, which needs an existing token: one of `--slot` or `--token`.
#[derive(Args)]
#[group(required = true, multiple = false)]
struct TargetSlotArg {
    /// Target a specific slot by id.
    #[arg(long)]
    slot: Option<u64>,

    /// Target the slot whose token has this label.
    #[arg(long)]
    token: Option<String>,
}

impl TargetSlotArg {
    fn selector(self) -> SlotSelector {
        match (self.slot, self.token) {
            (Some(id), _) => SlotSelector::Slot(id),
            (_, Some(label)) => SlotSelector::Token(label),
            _ => unreachable!("clap guarantees one of --slot/--token is set"),
        }
    }
}

fn main() {
    let cli = Cli::parse();

    if let Some(database) = cli.database {
        std::env::set_var("RUSTSSM_DATABASE_URL", database);
    }

    if let Err(message) = run(cli.command) {
        eprintln!("error: {message}");
        exit(1);
    }
}

fn run(command: Command) -> Result<(), String> {
    match command {
        Command::ShowSlots => {
            for slot in admin::show_slots().map_err(|error| error.to_string())? {
                let state = if slot.initialized {
                    let pin = if slot.user_pin_set { ", user PIN set" } else { "" };
                    format!("token {:?}{pin}", slot.label.as_deref().unwrap_or(""))
                } else {
                    String::from("uninitialized")
                };
                println!("Slot {}: {state}", slot.slot_id);
            }
        }
        Command::InitToken(args) => {
            let slot = admin::init_token(args.slot.selector(), args.label, args.so_pin, args.user_pin)
                .map_err(|error| error.to_string())?;
            println!("token on slot {slot} initialized");
        }
        Command::Import(args) => {
            if !args.aes {
                return Err(String::from("only --aes import is supported"));
            }
            let key = std::fs::read(&args.key_file)
                .map_err(|error| format!("cannot read {}: {error}", args.key_file.display()))?;
            let id = args.id.as_deref().map(parse_hex).transpose()?;
            let label = args.label.clone();
            admin::import_aes_key(args.target.selector(), args.user_pin, key, args.label, id)
                .map_err(|error| error.to_string())?;
            println!("imported AES key {label:?}");
        }
    }
    Ok(())
}
