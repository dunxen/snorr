use clap::{CommandFactory, Parser, Subcommand};
use rand::prelude::ThreadRng;
use schnorr_fun::{KeyPair, fun::{nonce, Scalar}, Schnorr};
use sha2::Sha256;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// generates a random keypair
    Generate {},
    /// verifiy a given Schnorr signature
    Verify {
        public_key: String,
        signature: String,
        message: String,
    },
}

fn generate_keypair() -> KeyPair {
    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen);
    let secret_key = Scalar::random(&mut rand::thread_rng());
    schnorr.new_keypair(secret_key)
}

fn main() {
    let cli = Cli::parse();
    let mut cmd = Cli::command();

    match cli.command {
        Some(Commands::Generate {}) => {
            let keypair = generate_keypair();
            println!("Public key: {}", keypair.public_key());
        }
        Some(Commands::Verify { .. }) => {
            // TODO: Verification
        }
        None => {
            cmd.print_help().expect("help should not fail");
        }
    }
}
