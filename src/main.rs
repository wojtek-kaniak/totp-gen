use std::{collections::HashMap, fs::{self, File, OpenOptions}, io::{self, BufReader, BufWriter, Seek, Write}, os::unix::fs::MetadataExt, path::{Path, PathBuf}, time::SystemTime};

use anyhow::{anyhow, Context};
use clap::{Args, Parser, Subcommand};
use hmac::{Hmac, Mac};
use sha1::Sha1;

#[derive(Debug, Clone, Parser)]
#[command(author, version)]
struct Cli {
    #[command(subcommand)]
    subcommand: CliCommand,
}

#[derive(Debug, Clone, Subcommand)]
enum CliCommand {
    #[command(aliases = ["gen", "g"])]
    Generate(GenerateCommand),

    New(NewCommand),

    #[command(aliases = ["remove"])]
    Delete(DeleteCommand),
}

#[derive(Debug, Clone, Args)]
struct GenerateCommand {
    service: String,
}

#[derive(Debug, Clone, Args)]
struct NewCommand {
    service: String,
    secret: Option<String>,
}

#[derive(Debug, Clone, Args)]
struct DeleteCommand {
    service: String,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let config_dir = dirs::config_local_dir()
        .context("config directory not available")?
        .extend_path(Path::new("totp-gen"));

    fs::create_dir_all(&config_dir)?;

    let key_store = config_dir.extend_path(Path::new("keys.json"));

    let mut key_store = match cli.subcommand {
        CliCommand::Generate(_) => OpenOptions::new()
            .read(true)
            .open(key_store),
        CliCommand::New(_) | CliCommand::Delete(_) => OpenOptions::new()
            .create(true).truncate(false).read(true).write(true)
            .open(key_store),
    }?;

    // TODO: refactor file operations

    // initialize the key store:
    if key_store.metadata()?.size() == 0 {
        key_store.write_all("{}".as_bytes())?;
        key_store.set_len(0)?;
    }

    match cli.subcommand {
        CliCommand::Generate(cmd)
            => get_key(&mut key_store, cmd.service.clone())
            .and_then(|otp| {
                let secret = otp.ok_or(anyhow!("service '{}' doesn't exist", cmd.service))?;
                let code = generate_otp(&secret)?;
                println!("{:06}", code);
                Ok(())
            }),
        CliCommand::New(cmd)
            => new_key(
                &mut key_store,
                cmd.service,
                cmd.secret.ok_or(()).or_else(|_| prompt_for_secret())?
            ),
        CliCommand::Delete(cmd)
            => delete_key(&mut key_store, cmd.service),
    }?;

    Ok(())
}

fn generate_otp(secret: &str) -> anyhow::Result<u32> {
    const TIME_SPAN_SECS: u64 = 30;
    const DIGITS: u32 = 6;

    let secret = base32::decode(base32::Alphabet::Rfc4648Lower { padding: false }, secret)
        .context("key store corrupted, invalid secret")?;

    // TOTP, see RFC 6238, https://datatracker.ietf.org/doc/html/rfc6238

    let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();

    let time_counter = now.as_secs() / TIME_SPAN_SECS;

    let mut hmac = Hmac::<Sha1>::new_from_slice(&secret).unwrap();

    hmac.update(&time_counter.to_be_bytes());

    let hmac = hmac.finalize().into_bytes();

    // HOTP, see RFC 4226, https://datatracker.ietf.org/doc/html/rfc4226

    let offset = (hmac[19] & 0xf) as usize;

    let code = ((hmac[offset] & 0x7f) as u32) << 24
        | (hmac[offset + 1] as u32) << 16
        | (hmac[offset + 2] as u32) << 8
        | (hmac[offset + 3] as u32);

    Ok(code % 10_u32.pow(DIGITS))
}

fn get_key(key_store: &mut File, service: String) -> anyhow::Result<Option<String>> {
    let reader = BufReader::new(&mut *key_store);

    let mut keys: Keys = serde_json::from_reader(reader)
        .context("key store corrupted")?;

    Ok(keys.remove(&service))
}

fn new_key(key_store: &mut File, service: String, code: String) -> anyhow::Result<()> {
    let reader = BufReader::new(&mut *key_store);

    let mut keys: Keys = serde_json::from_reader(reader)
        .context("key store corrupted")?;

    if keys.contains_key("service") {
        return Err(anyhow!("service '{}' already present", service));
    }

    keys.insert(service, code.to_lowercase());

    key_store.seek(std::io::SeekFrom::Start(0))?;
    key_store.set_len(0)?;

    let writer = BufWriter::new(key_store);

    serde_json::ser::to_writer_pretty(writer, &keys)?;

    Ok(())
}

fn delete_key(key_store: &mut File, service: String) -> anyhow::Result<()> {
    let reader = BufReader::new(&mut *key_store);

    let mut keys: Keys = serde_json::from_reader(reader)
        .context("key store corrupted")?;

    keys.remove(&service)
        .ok_or(anyhow!("service '{}' doesn't exist", service))?;

    key_store.seek(std::io::SeekFrom::Start(0))?;
    key_store.set_len(0)?;

    let writer = BufWriter::new(key_store);

    serde_json::ser::to_writer_pretty(writer, &keys)?;

    Ok(())
}

fn prompt_for_secret() -> anyhow::Result<String> {
    eprintln!("Secret:");
    io::stdin().lines().next()
        .context("stdin unavailable")?
        .context("invalid UTF-8")
}

type Keys = HashMap<String, String>;

trait PathBufExt {
    fn extend_path(self, path: &Path) -> Self;
}

impl PathBufExt for PathBuf {
    fn extend_path(mut self, path: &Path) -> Self {
        self.push(path);
        self
    }
}