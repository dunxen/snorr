use std::str::FromStr;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use rand::prelude::ThreadRng;
use schnorr_fun::{
    fun::{marker::Public, nonce, Scalar, XOnly},
    KeyPair, Message, Schnorr, Signature,
};
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

fn generate_keypair(
    schnorr: Schnorr<Sha256, nonce::Synthetic<Sha256, nonce::GlobalRng<ThreadRng>>>,
) -> KeyPair {
    let secret_key = Scalar::random(&mut rand::thread_rng());
    schnorr.new_keypair(secret_key)
}

fn new_schnorr() -> Schnorr<Sha256, nonce::Synthetic<Sha256, nonce::GlobalRng<ThreadRng>>> {
    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    Schnorr::<Sha256, _>::new(nonce_gen)
}

fn verify_signature(public_key: String, signature: String, message: String) -> Result<bool> {
    let verification_key = XOnly::from_str(&public_key)
        .context("public key invalid")?
        .to_point();
    let message_bytes = hex::decode(message)?;
    let message = Message::<Public>::raw(&message_bytes);
    let signature =
        Signature::<Public>::from_str(&signature).context("signature could not be parsed")?;
    let schnorr = new_schnorr();
    Ok(schnorr.verify(&verification_key, message, &signature))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut cmd = Cli::command();

    match cli.command {
        Some(Commands::Generate {}) => {
            let keypair = generate_keypair(new_schnorr());
            println!("Public key: {}", keypair.public_key());
        }
        Some(Commands::Verify {
            public_key,
            signature,
            message,
        }) => {
            if verify_signature(public_key, signature, message)? {
                println!("Valid Schnorr signature!");
            } else {
                println!("Invalid Schnorr signature");
            }
        }
        None => {
            cmd.print_help().expect("help should not fail");
        }
    }

    Ok(())
}
