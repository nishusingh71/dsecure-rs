//! `cargo xtask provision-keys`: staging ke liye REAL (non-dev) keys, `KEK_PROVIDER=env` design ke andar.
//!
//! Do alag steps (dusra explicit subcommand, DB sirf wahi chhuta hai):
//!
//! 1. `provision-keys [--env staging] [--out <file>] [--force] [--allow-no-git]`
//!    - Fresh KEK: id `STAGING_<12 hex>` (dev fingerprint kabhi nahi), value = random 32 bytes base64.
//!    - JWT kids: `jwt-member-staging-<hex>` / `jwt-staff-staging-<hex>`.
//!    - Env-style file (default `<repo>/.dev/staging.keys.env`, gitignored): `KEK_PROVIDER`,
//!      `KEK_ENV_ACTIVE_ID`, `KEK_ENV_<id>` (THE secret), `JWT_SIGNING_KID_MEMBER/_STAFF`. Private signing
//!      keys file mein NAHI jaati: design ke hisaab se woh sirf `signing_keys` table mein rehti hain (Secrets
//!      DEK se encrypted, DEK `data_keys` mein KEK se wrapped). Isliye step 2 unhe DB mein hi generate karta hai.
//!    - Write path (fail closed): temp file `create_new` (unix 0600) -> permissions restrict + verify
//!      (Windows `icacls`) -> TABHI secret bytes -> fsync -> atomic rename. Restrict fail = temp delete +
//!      error. Symlink target refuse. Existing file sirf `--force` se replace hoti hai, aur purani file
//!      `<name>.bak-<UTC timestamp>-<hex>` ban kar rehti hai (loud warning: purani KEK wala data uske bina
//!      unreadable).
//!    - Git work tree ke andar non-ignored path refuse; git na mile to bhi refuse (`--allow-no-git` ke bina).
//!    - Output (stderr; stdout par kuch nahi): sirf ids, kids, paths. Secret value kabhi print nahi hoti.
//!
//! 2. `provision-keys seed-db --keys-file <file> --db-url-env <VAR> [--tls-ca-env <VAR>]
//!     --approver <staff-user-uuid> --owner-approval-ref <ref> [--env staging|test]`
//!    - URL sirf env var ke NAAM se (`--db-url-env`), kabhi CLI literal nahi; platform-admin DB user
//!      (`rs_padm`, staging mein `CURRENT_USER()` check `PlatformAdminDb::connect` karta hai).
//!    - Refuse: legacy database (`config::dburl::targets_legacy_db`) aur koi bhi `cloud_erase*` naam;
//!      staging mein `ssl-mode=VERIFY_IDENTITY` + CA zaroori; `test` sirf loopback host par.
//!    - Order (sab kuch EK commit mein):
//!      a. Plan + KEK guard (read-only, kuch likhne se pehle): har maujood active platform DEK isi KEK
//!      (`kek_ref`) se wrapped ho aur unwrap ho, warna refuse (do KEKs wala mixed state DELETE ke bina
//!      theek nahi hota). Missing purposes ke liye naye kids chune jaate hain (audit row mein naam).
//!      b. `ops_tx_owner_approved` (`platform.keys.rotate`): claimed approver ACTIVE `platform_superadmin`
//!      hona chahiye (tx ke andar, row locked), owner approval ref zaroori; audit row isi tx mein.
//!      c. Tx ke andar state dobara check (plan se alag = abort), missing DEKs
//!      `repo::keys::insert_platform_dek_in_tx` se. `staff-bootstrap` ne DEKs bana di hon to 0 nayi.
//!      KeyRing in-memory store se (nayi DEKs abhi uncommitted hain).
//!      d. ES256 member + staff JWT keys aur Ed25519 report key `signing_keys::insert_signing_key` se.
//!      e. Ek commit: DEKs + signing keys + audit row. Koi bhi fail = poora rollback.
//!    - Audit: approver sirf CLI operator ka DAAVA hai (DB credentials, koi staff session/MFA nahi), isliye
//!      row `actor_kind = system`, `actor_id` NULL, metadata `actor = ops_cli`, `claimed_approver`,
//!      `approver_proof = "claimed"`, `owner_approval_ref`, kids.
//!    - Commit ke baad `api::keys::load_jwt` wahi check chalata hai jo api startup karta hai.

use anyhow::{Context, Result, anyhow, bail};
use common::UserId;
use common::config_util::Env;
use config::Environment;
use crypto::{
    AesGcmFieldEncryptor, DekStore as _, Ed25519Signer, EnvKeyProvider, Es256Signer, KeyProvider,
    KeyRing, SigAlg, is_dev_fingerprint,
};
use db::DbDekStore;
use db::platform_admin::PlatformAdminDb;
use db::repo::audit::AuditRowRecord;
use db::repo::signing_keys::{self, NewSigningKey, SigningRealm};
use domain::rbac::PlatformPerm;
use secrecy::{ExposeSecret as _, SecretString};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::OffsetDateTime;
use zeroize::Zeroizing;

const USAGE: &str = "usage:\n  \
    cargo xtask provision-keys [--env staging] [--out <file>] [--force] [--allow-no-git]\n  \
    cargo xtask provision-keys seed-db --keys-file <file> --db-url-env <VAR> [--tls-ca-env <VAR>] \
    --approver <staff-user-uuid> --owner-approval-ref <ref> [--env staging|test]";

/// Report line (value-free). Write errors are ignored: the report is informational.
macro_rules! line {
    ($w:expr, $($arg:tt)*) => { let _ = writeln!($w, $($arg)*); };
}

/// Permission restriction hook (tests inject a failing one).
type Restrict = fn(&Path) -> Result<()>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct FileOpts {
    force: bool,
    allow_no_git: bool,
}

pub fn run(args: impl Iterator<Item = String>) -> Result<()> {
    let args: Vec<String> = args.collect();
    let mut stderr = std::io::stderr();
    if args.first().map(String::as_str) == Some("seed-db") {
        let a = SeedArgs::parse(args.get(1..).unwrap_or_default())?;
        return seed_cli(&a, &Env::process(), &mut stderr).map(|_| ());
    }
    let mut env_name = String::from("staging");
    let mut out: Option<PathBuf> = None;
    let mut opts = FileOpts::default();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--force" => opts.force = true,
            "--allow-no-git" => opts.allow_no_git = true,
            "--out" => out = Some(PathBuf::from(it.next().context("--out needs a file path")?)),
            "--env" => env_name = it.next().context("--env needs a value")?,
            other => bail!("unknown argument `{other}`\n{USAGE}"),
        }
    }
    let env = file_env(&env_name)?;
    let out = match out {
        Some(p) => p,
        // Anchored at the repo root (not the cwd), so the default always lands in the ignored `.dev/`.
        None => crate::gates::repo_root()?
            .join(".dev")
            .join(format!("{env}.keys.env")),
    };
    generate_file(env, &out, opts, strict_restrict, &mut stderr).map(|_| ())
}

/// Environments the file step serves. Only staging: dev/test have `dev-keys`, production needs
/// `KEK_PROVIDER=azure-kv` (the env provider is refused there by `config`).
fn file_env(name: &str) -> Result<&'static str> {
    match name {
        "staging" => Ok("staging"),
        "production" => bail!(
            "provision-keys refuses production: KEK_PROVIDER=env is not allowed there (azure-kv, not built yet)"
        ),
        "dev" | "test" => bail!("for dev/test use `cargo xtask dev-keys`"),
        _ => bail!("--env must be `staging`"),
    }
}

/// Random lowercase hex (ids/kids/temp names only, not key material): the random tail of a UUIDv7.
fn rand_hex(n: usize) -> String {
    let s = uuid::Uuid::now_v7().simple().to_string();
    s.get(s.len().saturating_sub(n.min(12))..)
        .unwrap_or("0")
        .to_owned()
}

/// Ids written into the file (none of them secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provisioned {
    pub kek_id: String,
    pub member_kid: String,
    pub staff_kid: String,
    pub path: PathBuf,
    /// Previous file kept by `--force` (still holds the OLD secret, permissions unchanged).
    pub backup: Option<PathBuf>,
}

fn fresh_ids(env: &str) -> Result<(String, String, String)> {
    for _ in 0..8 {
        let kek_id = format!(
            "{}_{}",
            env.to_ascii_uppercase(),
            rand_hex(12).to_ascii_uppercase()
        );
        let member = format!("jwt-member-{env}-{}", rand_hex(8));
        let staff = format!("jwt-staff-{env}-{}", rand_hex(8));
        if [&kek_id, &member, &staff]
            .iter()
            .all(|s| !is_dev_fingerprint(s))
            && member != staff
        {
            return Ok((kek_id, member, staff));
        }
    }
    bail!("could not generate non-dev key ids")
}

/// Refuse a path inside a git work tree that git would NOT ignore (secrets must never be committable).
/// Outside any work tree: allowed. Git not runnable: refused unless `allow_no_git`.
fn ensure_not_committable(path: &Path, allow_no_git: bool, report: &mut dyn Write) -> Result<()> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("current directory")?
            .join(path)
    };
    let mut dir = abs.parent().map(Path::to_path_buf);
    while let Some(d) = &dir {
        if d.exists() {
            break;
        }
        dir = d.parent().map(Path::to_path_buf);
    }
    let Some(dir) = dir else {
        bail!("no existing parent directory for {}", path.display())
    };
    let git = |args: &[&std::ffi::OsStr]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
    };
    let inside = match git(&["rev-parse".as_ref(), "--is-inside-work-tree".as_ref()]) {
        Ok(o) => o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "true",
        Err(_) if allow_no_git => {
            line!(
                report,
                "warning: git not available; NOT checked that {} is gitignored (--allow-no-git)",
                path.display()
            );
            return Ok(());
        }
        Err(_) => bail!(
            "refusing: git is not available, so it cannot be checked that {} is gitignored \
             (install git, or pass --allow-no-git for a path outside any repository)",
            path.display()
        ),
    };
    if !inside {
        return Ok(());
    }
    let ignored = git(&[
        "check-ignore".as_ref(),
        "-q".as_ref(),
        "--".as_ref(),
        abs.as_os_str(),
    ])
    .map(|o| o.status.code())
    .map_err(|_| anyhow!("git check-ignore could not run"))?;
    if ignored == Some(0) {
        Ok(())
    } else {
        bail!(
            "refusing to write secrets to {}: it is inside a git work tree and NOT gitignored \
             (use the default under .dev/ or a path outside the repository)",
            path.display()
        )
    }
}

/// Mandatory restriction: owner-only access, verified afterwards. Error = caller deletes the file.
fn strict_restrict(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = if path.is_dir() { 0o700 } else { 0o600 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {}", path.display()))?;
        let got = fs::symlink_metadata(path)?.permissions().mode();
        if got & 0o077 != 0 {
            bail!("{} is still accessible to group/others", path.display());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let user = std::env::var_os("USERNAME").context("USERNAME not set")?;
        let mut who = user.to_string_lossy().into_owned();
        if let Some(domain) = std::env::var_os("USERDOMAIN") {
            who = format!("{}\\{who}", domain.to_string_lossy());
        }
        let perm = if path.is_dir() { "(OI)(CI)F" } else { "F" };
        let icacls = |args: &[&str]| {
            std::process::Command::new("icacls")
                .arg(path)
                .args(args)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .output()
        };
        // Grant self first, then drop inheritance (reverse order could lock the user out).
        for args in [
            vec!["/grant:r".to_owned(), format!("{who}:{perm}")],
            vec!["/inheritance:r".to_owned()],
        ] {
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            let o = icacls(&a).context("icacls could not run")?;
            if !o.status.success() {
                bail!("icacls failed on {}", path.display());
            }
        }
        let o = icacls(&[]).context("icacls could not run")?;
        let text = String::from_utf8_lossy(&o.stdout).to_lowercase();
        for banned in ["everyone", "builtin\\users", "authenticated users"] {
            if text.contains(banned) {
                bail!("{} still grants `{banned}`", path.display());
            }
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        bail!(
            "cannot restrict permissions on this platform: {}",
            path.display()
        )
    }
}

/// `YYYYMMDDTHHMMSSZ` (UTC) for backup names.
fn stamp() -> String {
    let t = OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// Secret file write: temp (`create_new`, never follows a symlink) -> `restrict` -> bytes -> fsync ->
/// existing file renamed to a backup (only with `force`) -> atomic rename. Any failure before the final
/// rename leaves the old file untouched and removes the temp file.
fn write_secret_file(
    out: &Path,
    data: &[u8],
    force: bool,
    restrict: Restrict,
) -> Result<Option<PathBuf>> {
    let existing = match fs::symlink_metadata(out) {
        Ok(m) if m.file_type().is_symlink() => {
            bail!("refusing: {} is a symlink", out.display())
        }
        Ok(m) if m.is_dir() => bail!("--out must be a file path, not a directory"),
        Ok(_) if !force => bail!(
            "refusing to overwrite existing file {} (use --force)",
            out.display()
        ),
        Ok(_) => true,
        Err(_) => false,
    };
    let name = out
        .file_name()
        .and_then(|n| n.to_str())
        .context("--out needs a file name")?;
    let dir = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(".{name}.tmp-{}", rand_hex(12)));
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    let mut f = o
        .open(&tmp)
        .with_context(|| format!("create {}", tmp.display()))?;
    let written = restrict(&tmp)
        .context("could not restrict permissions (nothing written)")
        .and_then(|()| {
            f.write_all(data)
                .and_then(|()| f.sync_all())
                .with_context(|| format!("write {}", tmp.display()))
        });
    drop(f);
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    let backup = if existing {
        let bak = dir.join(format!("{name}.bak-{}-{}", stamp(), rand_hex(4)));
        if let Err(e) = fs::rename(out, &bak) {
            let _ = fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("back up {}", out.display()));
        }
        Some(bak)
    } else {
        None
    };
    if let Err(e) = fs::rename(&tmp, out) {
        if let Some(b) = &backup {
            let _ = fs::rename(b, out);
        }
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("rename into {}", out.display()));
    }
    Ok(backup)
}

fn generate_file(
    env: &str,
    out: &Path,
    opts: FileOpts,
    restrict: Restrict,
    report: &mut dyn Write,
) -> Result<Provisioned> {
    if out.is_dir() {
        bail!("--out must be a file path, not a directory");
    }
    if out.exists() && !opts.force {
        bail!(
            "refusing to overwrite existing file {} (use --force)",
            out.display()
        );
    }
    ensure_not_committable(out, opts.allow_no_git, report)?;
    // The backup (old secret) and the temp file live next to `out`: they must be ignored too.
    if let Some(name) = out.file_name().and_then(|n| n.to_str()) {
        for sibling in [format!("{name}.bak-check"), format!(".{name}.tmp-check")] {
            ensure_not_committable(&out.with_file_name(sibling), opts.allow_no_git, report)?;
        }
    }
    if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty())
        && !parent.exists()
    {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        restrict(parent).context("could not restrict the new output directory")?;
    }

    let (kek_id, member_kid, staff_kid) = fresh_ids(env)?;
    let kek_b64 = crypto::devkeys::generate_kek_b64()?;
    // Same acceptance as api startup (`load_keyring`): parses, 32 bytes, not dev.
    let provider = EnvKeyProvider::new(&kek_id, [(kek_id.clone(), (*kek_b64).clone())])?;
    if provider.is_dev() {
        bail!("generated KEK id carries the dev marker (refused)");
    }

    let text = Zeroizing::new(format!(
        "# Generated by `cargo xtask provision-keys` for DSECURE_ENV={env}.\n\
         # SECRET: the KEK_ENV_{kek_id} value. Paste each line into the Render dashboard (secret env vars),\n\
         # then move this file offline or delete it. Never commit it, never paste it into chat or tickets.\n\
         # Losing the KEK makes every DEK in data_keys (and all data encrypted under it) unreadable.\n\
         # Signing private keys are NOT in this file: `provision-keys seed-db` creates them inside signing_keys.\n\
         KEK_PROVIDER=env\n\
         KEK_ENV_ACTIVE_ID={kek_id}\n\
         KEK_ENV_{kek_id}={}\n\
         JWT_SIGNING_KID_MEMBER={member_kid}\n\
         JWT_SIGNING_KID_STAFF={staff_kid}\n",
        *kek_b64,
    ));
    let backup = write_secret_file(out, text.as_bytes(), opts.force, restrict)?;

    if let Some(b) = &backup {
        line!(
            report,
            "WARNING: --force replaced {} with a NEW KEK.",
            out.display()
        );
        line!(
            report,
            "WARNING: if the old KEK was already used (seed-db ran, or Render has it), everything encrypted \
             under it is unreadable without the old file. seed-db refuses a database whose DEKs use another KEK."
        );
        line!(
            report,
            "WARNING: old file kept (contains the OLD secret): {}",
            b.display()
        );
    }
    line!(
        report,
        "provision-keys ({env}): written (no secret values shown)"
    );
    line!(report, "  file                   : {}", out.display());
    line!(report, "  KEK_ENV_ACTIVE_ID      : {kek_id}");
    line!(report, "  JWT_SIGNING_KID_MEMBER : {member_kid}");
    line!(report, "  JWT_SIGNING_KID_STAFF  : {staff_kid}");
    line!(
        report,
        "  next: run migrations, then `cargo xtask provision-keys seed-db --keys-file {}` (docs/ops/RENDER_SETUP.md)",
        out.display()
    );
    Ok(Provisioned {
        kek_id,
        member_kid,
        staff_kid,
        path: out.to_path_buf(),
        backup,
    })
}

/// Parsed keys file (step 1 output).
pub struct KeysFile {
    pub kek_id: String,
    pub kek_b64: Zeroizing<String>,
    pub member_kid: String,
    pub staff_kid: String,
}

impl std::fmt::Debug for KeysFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeysFile")
            .field("kek_id", &self.kek_id)
            .field("member_kid", &self.member_kid)
            .field("staff_kid", &self.staff_kid)
            .finish_non_exhaustive()
    }
}

/// Value-free errors (only key names).
fn parse_keys_file(text: &str) -> Result<KeysFile> {
    let mut m = std::collections::HashMap::new();
    for l in text.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            m.insert(k.trim().to_owned(), Zeroizing::new(v.trim().to_owned()));
        }
    }
    let get = |k: &str| {
        m.get(k)
            .map(|v| v.to_string())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow!("keys file: `{k}` missing"))
    };
    if get("KEK_PROVIDER")? != "env" {
        bail!("keys file: KEK_PROVIDER must be `env`");
    }
    let kek_id = get("KEK_ENV_ACTIVE_ID")?;
    let kek_b64 = Zeroizing::new(get(&format!("KEK_ENV_{kek_id}"))?);
    Ok(KeysFile {
        kek_id,
        kek_b64,
        member_kid: get("JWT_SIGNING_KID_MEMBER")?,
        staff_kid: get("JWT_SIGNING_KID_STAFF")?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SeedArgs {
    keys_file: PathBuf,
    db_url_env: String,
    tls_ca_env: String,
    approver: uuid::Uuid,
    owner_approval_ref: String,
    env: Environment,
}

/// `^[A-Z_][A-Z0-9_]*$`: an env var NAME. Anything URL-like is refused so a URL never lands in shell history.
fn env_var_name(flag: &str, v: &str) -> Result<String> {
    let ok = v
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_uppercase() || b == b'_')
        && v.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if !ok {
        bail!(
            "{flag} takes the NAME of an environment variable (e.g. DSECURE_STAGING_ADMIN_URL), \
             never a URL or other value"
        );
    }
    Ok(v.to_owned())
}

impl SeedArgs {
    fn parse(args: &[String]) -> Result<Self> {
        let mut keys_file = None;
        let mut db_url_env = None;
        let mut tls_ca_env = String::from("DB_TLS_CA");
        let mut approver = None;
        let mut owner_ref = None;
        let mut env = Environment::Staging;
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let mut val = || {
                it.next()
                    .cloned()
                    .ok_or_else(|| anyhow!("{a} needs a value\n{USAGE}"))
            };
            match a.as_str() {
                "--keys-file" => keys_file = Some(PathBuf::from(val()?)),
                "--db-url-env" => db_url_env = Some(env_var_name(a, &val()?)?),
                "--tls-ca-env" => tls_ca_env = env_var_name(a, &val()?)?,
                "--approver" => {
                    approver = Some(
                        uuid::Uuid::parse_str(&val()?)
                            .map_err(|_| anyhow!("--approver must be a staff user UUID"))?,
                    );
                }
                "--owner-approval-ref" => owner_ref = Some(val()?),
                "--env" => {
                    env = match val()?.as_str() {
                        "staging" => Environment::Staging,
                        "test" => Environment::Test,
                        _ => bail!(
                            "seed-db --env must be `staging` (or `test` for a local loopback DB)"
                        ),
                    };
                }
                "--db-url" => {
                    bail!("--db-url is not supported: pass --db-url-env <NAME OF ENV VAR> instead")
                }
                other => bail!("unknown seed-db argument `{other}`\n{USAGE}"),
            }
        }
        Ok(Self {
            keys_file: keys_file.ok_or_else(|| anyhow!("--keys-file missing\n{USAGE}"))?,
            db_url_env: db_url_env.ok_or_else(|| anyhow!("--db-url-env missing\n{USAGE}"))?,
            tls_ca_env,
            approver: approver.ok_or_else(|| anyhow!("--approver missing\n{USAGE}"))?,
            owner_approval_ref: owner_ref
                .ok_or_else(|| anyhow!("--owner-approval-ref missing\n{USAGE}"))?,
            env,
        })
    }
}

/// Host part of a mysql URL (`user:pw@host:port/db`), lowercase, brackets stripped.
fn url_host(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let auth_host = rest.split(['/', '?']).next().unwrap_or("");
    let hostport = auth_host.rsplit_once('@').map_or(auth_host, |(_, h)| h);
    let host = if let Some(h) = hostport.strip_prefix('[') {
        h.split(']').next().unwrap_or("")
    } else {
        hostport.split(':').next().unwrap_or("")
    };
    host.to_ascii_lowercase()
}

/// Value-free target refusals (before any connection).
fn check_target(url: &str, env: Environment, tls_ca: Option<&SecretString>) -> Result<()> {
    if config::dburl::targets_legacy_db(url) {
        bail!("refused: the URL points at the legacy database (never touched)");
    }
    if config::dburl::database_names(url)
        .iter()
        .any(|n| n.to_ascii_lowercase().starts_with("cloud_erase"))
    {
        bail!("refused: cloud_erase* databases are never touched");
    }
    if !config::dburl::is_mysql_url(url) {
        bail!("refused: not a valid mysql:// URL with a plain database name (no cert/socket keys)");
    }
    if env.is_local() {
        if !matches!(url_host(url).as_str(), "localhost" | "127.0.0.1" | "::1") {
            bail!("refused: --env test is only for a loopback (local) database");
        }
    } else {
        if !config::dburl::has_verified_tls(url) {
            bail!("refused: staging needs exactly one ssl-mode=VERIFY_IDENTITY in the URL");
        }
        if tls_ca.is_none_or(|c| c.expose_secret().trim().is_empty()) {
            bail!("refused: staging needs the CA bundle (--tls-ca-env, default DB_TLS_CA)");
        }
    }
    Ok(())
}

/// What `seed` did (no secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedOutcome {
    pub deks_created: usize,
    pub member_kid: String,
    pub staff_kid: String,
    pub report_kid: String,
}

fn now_micros() -> OffsetDateTime {
    let t = OffsetDateTime::now_utc();
    t.replace_nanosecond(t.nanosecond() / 1000 * 1000)
        .unwrap_or(t)
}

fn seed_cli(a: &SeedArgs, env: &Env, report: &mut dyn Write) -> Result<SeedOutcome> {
    let text = Zeroizing::new(
        fs::read_to_string(&a.keys_file)
            .with_context(|| format!("read keys file {}", a.keys_file.display()))?,
    );
    let keys = parse_keys_file(&text)?;
    let url = env
        .optional(&a.db_url_env)
        .map_err(|_| anyhow!("`{}` is not valid unicode", a.db_url_env))?
        .ok_or_else(|| anyhow!("environment variable `{}` is not set", a.db_url_env))?;
    let tls_ca = env
        .optional(&a.tls_ca_env)
        .map_err(|_| anyhow!("`{}` is not valid unicode", a.tls_ca_env))?
        .map(SecretString::from);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("tokio runtime")?;
    rt.block_on(seed(
        SecretString::from(url),
        tls_ca,
        a.env,
        &keys,
        UserId(a.approver),
        &a.owner_approval_ref,
        report,
    ))
}

async fn seed(
    url: SecretString,
    tls_ca: Option<SecretString>,
    env: Environment,
    keys: &KeysFile,
    approver: UserId,
    owner_approval_ref: &str,
    report: &mut dyn Write,
) -> Result<SeedOutcome> {
    check_target(url.expose_secret(), env, tls_ca.as_ref())?;
    if !env.is_local() {
        for (k, v) in [
            ("KEK_ENV_ACTIVE_ID", &keys.kek_id),
            ("JWT_SIGNING_KID_MEMBER", &keys.member_kid),
            ("JWT_SIGNING_KID_STAFF", &keys.staff_kid),
        ] {
            if is_dev_fingerprint(v) {
                bail!("refused: {k} is a dev key (staging refuses dev keys)");
            }
        }
    }
    let provider: Arc<dyn KeyProvider> = Arc::new(
        EnvKeyProvider::new(
            &keys.kek_id,
            [(keys.kek_id.clone(), (*keys.kek_b64).clone())],
        )
        .context("KEK refused")?,
    );
    if provider.is_dev() && !env.is_local() {
        bail!("refused: dev KEK outside dev/test");
    }

    let cfg = config::DbConfig {
        url,
        tls_ca,
        expect_engine: if env.is_local() {
            config::DbEngine::MySql
        } else {
            config::DbEngine::TiDb
        },
        // Admin tx holds one connection; DEK store + post-check need others.
        max_connections: 3,
        acquire_timeout_ms: 10_000,
        tx_timeout_ms: 10_000,
        max_execution_ms: 10_000,
        lock_wait_timeout_s: 10,
        retry_max_attempts: 3,
        retry_base_delay_ms: 20,
        statement_cache_capacity: 0,
        migrator_url: None,
    };
    let admin = PlatformAdminDb::connect(&cfg, env)
        .await
        .context("connect as the platform-admin DB user")?;
    let r = seed_on(&admin, provider, keys, approver, owner_approval_ref).await;
    admin.db().close().await;
    let out = r?;
    line!(
        report,
        "provision-keys seed-db: committed (no key bytes shown)"
    );
    line!(report, "  platform DEKs created  : {}", out.deks_created);
    line!(report, "  JWT member key (ES256) : {}", out.member_kid);
    line!(report, "  JWT staff key (ES256)  : {}", out.staff_kid);
    line!(report, "  report key (Ed25519)   : {}", out.report_kid);
    line!(report, "  startup check (load_jwt): ok");
    Ok(out)
}

/// Plan + KEK guard (read-only, before any write): shared with `dsecure-api staff-bootstrap`
/// (`db::repo::keys::plan_platform_deks`, review N1). Existing active platform DEKs must be wrapped by
/// this KEK and unwrap with it; missing purposes get a fresh kid + DEK wrapped in memory.
async fn plan_deks(
    provider: &dyn KeyProvider,
    store: &DbDekStore,
) -> Result<Vec<db::repo::keys::PlatformDekPlan>> {
    db::repo::keys::plan_platform_deks(provider, store)
        .await
        .map_err(|e| anyhow!("refused: {e}"))
}

fn audit_row(
    action: &str,
    metadata: serde_json::Value,
    now: OffsetDateTime,
) -> Result<AuditRowRecord> {
    let mut a = AuditRowRecord {
        id: uuid::Uuid::now_v7(),
        occurred_at: now,
        tenant_id: None,
        actor_kind: "system".into(),
        actor_id: None,
        staff_grant_id: None,
        action: action.into(),
        outcome: "success".into(),
        target_type: Some("signing_keys".into()),
        target_id: None,
        request_id: None,
        ip_hmac: None,
        metadata: Some(metadata),
        row_hash: Vec::new(),
    };
    a.row_hash = audit::chain::compute_row_hash(&a)
        .map_err(|_| anyhow!("audit row hash failed"))?
        .to_vec();
    Ok(a)
}

#[allow(clippy::too_many_lines)]
async fn seed_on(
    admin: &PlatformAdminDb,
    provider: Arc<dyn KeyProvider>,
    keys: &KeysFile,
    approver: UserId,
    owner_approval_ref: &str,
) -> Result<SeedOutcome> {
    let now = now_micros();
    let report_kid = format!("report-{}", rand_hex(12));

    // a) Plan + KEK guard before anything is written.
    let plan = plan_deks(provider.as_ref(), &DbDekStore::new(admin.db().clone())).await?;
    let new_dek_kids: Vec<String> = plan
        .iter()
        .filter(|d| !d.existing)
        .map(|d| d.kid.to_string())
        .collect();

    // b) Ops-CLI tx: the approver is CLAIMED (DB credentials only), so the audit row is a system row
    //    (`actor` ops_cli) naming the claimed approver; the db still requires an active superadmin.
    let audit = audit_row(
        "keys.provision",
        serde_json::json!({
            "actor": db::platform_admin::OPS_CLI_ACTOR,
            "claimed_approver": approver.0.hyphenated().to_string(),
            "approver_proof": "claimed",
            "owner_approval_ref": owner_approval_ref.trim(),
            "tool": "xtask provision-keys seed-db",
            "kek_ref": provider.active_kek_ref(),
            "signing_kids": [keys.member_kid, keys.staff_kid, report_kid],
            "dek_kids_created": new_dek_kids,
        }),
        now,
    )?;
    let mut tx = admin
        .ops_tx_owner_approved(
            approver,
            PlatformPerm::KeysRotate,
            owner_approval_ref,
            &audit,
            now,
        )
        .await
        .context(
            "approver check refused (--approver must be an active platform_superadmin; \
             platform.keys.rotate needs an owner approval reference)",
        )?;

    let work = async {
        // c) Inside the tx: same state as planned (else abort), then the missing DEKs.
        let mem = Arc::new(crypto::InMemoryDekStore::new());
        for d in &plan {
            let now_in_tx = db::repo::keys::platform_active_in_tx(&mut tx, d.purpose).await?;
            match (d.existing, now_in_tx) {
                // Same row as planned (guarded by the plan: same KEK, unwraps).
                (true, Some((k, w))) if k == d.kid && w == d.wrapped => {
                    mem.insert(&k, d.purpose, None, &w).await?;
                }
                (false, None) => {
                    db::repo::keys::insert_platform_dek_in_tx(
                        &mut tx, &d.kid, d.purpose, &d.wrapped, now,
                    )
                    .await
                    .context("insert platform DEK")?;
                    mem.insert(&d.kid, d.purpose, None, &d.wrapped).await?;
                }
                _ => bail!("data_keys changed while seeding (another run?); nothing was written"),
            }
        }
        // The new DEKs are not committed yet: the KeyRing reads them from memory.
        let ring = KeyRing::load_platform(Arc::clone(&provider), mem)
            .await
            .context("platform DEKs could not be loaded with this KEK")?;
        let enc = AesGcmFieldEncryptor::new(Arc::new(ring));

        // d) Signing keys: generated here, encrypted by insert_signing_key, never written elsewhere.
        let mut new_keys = Vec::with_capacity(3);
        for (kid, realm) in [
            (&keys.member_kid, SigningRealm::JwtMember),
            (&keys.staff_kid, SigningRealm::JwtStaff),
        ] {
            let pk = Es256Signer::generate_pkcs8()?;
            let public_key = Es256Signer::from_pkcs8(kid.as_str(), &pk)?
                .public_key_bytes()
                .to_vec();
            new_keys.push(NewSigningKey {
                kid: kid.clone(),
                alg: SigAlg::Es256,
                realm,
                private_key: Zeroizing::new(pk.to_vec()),
                public_key,
                not_before: now - time::Duration::minutes(1),
                expires_at: None,
            });
        }
        let pk = Ed25519Signer::generate_pkcs8()?;
        let public_key = Ed25519Signer::from_pkcs8(report_kid.as_str(), &pk)?
            .public_key_bytes()
            .to_vec();
        new_keys.push(NewSigningKey {
            kid: report_kid.clone(),
            alg: SigAlg::Ed25519,
            realm: SigningRealm::ReportCertificate,
            private_key: Zeroizing::new(pk.to_vec()),
            public_key,
            not_before: now - time::Duration::minutes(1),
            expires_at: None,
        });
        for k in &new_keys {
            signing_keys::insert_signing_key(&mut tx, &enc, k, now)
                .await
                .with_context(|| format!("insert signing key `{}`", k.kid))?;
        }
        Ok::<_, anyhow::Error>(enc)
    }
    .await;
    let enc = match work {
        Ok(v) => v,
        Err(e) => {
            tx.rollback().await;
            return Err(e);
        }
    };
    // e) ONE commit: DEKs + signing keys + audit row.
    tx.commit().await.context("commit")?;

    // Same check the api runs at startup (fail closed there), now against the committed rows.
    api::keys::load_jwt(admin.db(), &enc, &keys.member_kid, &keys.staff_kid)
        .await
        .map_err(|e| anyhow!("post-check: api startup would refuse the JWT keys: {e}"))?;
    Ok(SeedOutcome {
        deks_created: new_dek_kids.len(),
        member_kid: keys.member_kid.clone(),
        staff_kid: keys.staff_kid.clone(),
        report_kid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{KeyPurpose, WrapContext};

    const OPTS: FileOpts = FileOpts {
        force: false,
        allow_no_git: false,
    };
    const FORCE: FileOpts = FileOpts {
        force: true,
        allow_no_git: false,
    };

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("dsecure-provision-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        p
    }

    fn gen_file(f: &Path, opts: FileOpts) -> Result<Provisioned> {
        generate_file("staging", f, opts, strict_restrict, &mut Vec::new())
    }

    fn failing_restrict(_: &Path) -> Result<()> {
        bail!("injected restrict failure")
    }

    fn pairs_of(text: &str) -> Vec<(String, String)> {
        text.lines()
            .filter(|l| !l.trim_start().starts_with('#') && l.contains('='))
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    fn dir_names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    /// Staging fixture (non-key settings), like `crypto::config_check` tests.
    fn staging_env(key_pairs: Vec<(String, String)>) -> Env {
        let mut p: Vec<(String, String)> = [
            ("DSECURE_ENV", "staging"),
            (
                "DATABASE_URL",
                "mysql://app:pw@db.example.com:4000/dsecure_rs_staging?ssl-mode=VERIFY_IDENTITY",
            ),
            ("DB_TLS_CA", "/etc/ssl/certs/ca-certificates.crt"),
            ("JWT_ISSUER", "https://staging.dsecure.test"),
            ("TRUSTED_PROXY_HOPS", "1"),
            ("TRUSTED_PROXY_CIDRS", "10.0.0.0/8"),
            ("BLOB_BACKEND", "fs"),
            ("BLOB_FS_ROOT", "/tmp/blobs"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        p.extend(key_pairs);
        Env::from_pairs(p)
    }

    #[test]
    fn generated_ids_are_not_dev_and_staging_config_accepts_them() {
        let dir = tmp("cfg");
        let f = dir.join("staging.keys.env");
        let p = gen_file(&f, OPTS).expect("generate");
        for id in [&p.kek_id, &p.member_kid, &p.staff_kid] {
            assert!(!is_dev_fingerprint(id), "{id}");
        }
        assert!(p.kek_id.starts_with("STAGING_"));
        let text = fs::read_to_string(&f).expect("read");
        let keys = parse_keys_file(&text).expect("parse");
        assert_eq!(keys.kek_id, p.kek_id);
        let provider = EnvKeyProvider::new(
            &keys.kek_id,
            [(keys.kek_id.clone(), (*keys.kek_b64).clone())],
        )
        .expect("provider accepts");
        assert!(!provider.is_dev());

        let env = staging_env(pairs_of(&text));
        let cfg = config::AppConfig::load_with(&env, &[&crypto::DevKeyCheck])
            .expect("staging config accepts generated keys");
        assert_eq!(cfg.environment, Environment::Staging);
        assert_eq!(cfg.kek.env_active_id.as_deref(), Some(p.kek_id.as_str()));
        assert_eq!(cfg.jwt.signing_kid_member, p.member_kid);
        assert_eq!(cfg.jwt.signing_kid_staff, p.staff_kid);
        api::startup::load(&env).expect("api startup config accepts");

        let mut dev_pairs = pairs_of(&text);
        let dev_id = crypto::devkeys::dev_kek_id().expect("dev id");
        for (k, v) in &mut dev_pairs {
            if k == "KEK_ENV_ACTIVE_ID" {
                v.clone_from(&dev_id);
            }
        }
        dev_pairs.push((format!("KEK_ENV_{dev_id}"), keys.kek_b64.to_string()));
        assert!(
            config::AppConfig::load_with(&staging_env(dev_pairs), &[&crypto::DevKeyCheck]).is_err()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn report_never_contains_the_secret() {
        let dir = tmp("report");
        let f = dir.join("k.env");
        let mut rep = Vec::new();
        let p = generate_file("staging", &f, OPTS, strict_restrict, &mut rep).expect("generate");
        let first = parse_keys_file(&fs::read_to_string(&f).expect("r")).expect("parse");
        // --force report (warning lines) must not leak the old or the new secret either.
        generate_file("staging", &f, FORCE, strict_restrict, &mut rep).expect("force");
        let second = parse_keys_file(&fs::read_to_string(&f).expect("r")).expect("parse");
        let report = String::from_utf8(rep).expect("utf8");
        assert!(report.contains(&p.kek_id) && report.contains(&p.member_kid));
        assert!(report.contains(&f.display().to_string()));
        assert!(report.contains("WARNING"));
        for s in [first.kek_b64.as_str(), second.kek_b64.as_str()] {
            assert!(!report.contains(s), "secret in report");
        }
        assert!(
            !report.contains("KEK_ENV_STAGING_"),
            "secret var line in report"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_overwrite_without_force_and_force_keeps_a_backup() {
        let dir = tmp("force");
        let f = dir.join("k.env");
        gen_file(&f, OPTS).expect("first");
        let before = fs::read(&f).expect("before");
        let e = gen_file(&f, OPTS).expect_err("must refuse");
        assert!(e.to_string().contains("--force"), "{e}");
        assert_eq!(
            fs::read(&f).expect("same"),
            before,
            "refused run changed the file"
        );
        let p = gen_file(&f, FORCE).expect("force");
        assert_ne!(fs::read(&f).expect("after"), before);
        let bak = p.backup.expect("backup kept");
        assert_eq!(fs::read(&bak).expect("bak"), before, "backup = old file");
        assert!(
            bak.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("k.env.bak-"))
        );
        assert!(
            !dir_names(&dir).iter().any(|n| n.contains(".tmp-")),
            "temp file left"
        );
        assert!(gen_file(&dir, FORCE).is_err(), "dir as --out");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_restrict_writes_nothing_and_keeps_the_old_file() {
        let dir = tmp("restrict");
        let f = dir.join("k.env");
        // New file: refused, no file, no temp left.
        let mut rep = Vec::new();
        fs::create_dir_all(&dir).expect("mkdir");
        let e = generate_file("staging", &f, OPTS, failing_restrict, &mut rep)
            .expect_err("restrict failure");
        assert!(format!("{e:#}").contains("injected"), "{e:#}");
        assert!(!f.exists());
        assert!(dir_names(&dir).is_empty(), "{:?}", dir_names(&dir));
        // Existing file + --force: old file intact, no backup, no temp.
        gen_file(&f, OPTS).expect("real file");
        let before = fs::read(&f).expect("before");
        assert!(generate_file("staging", &f, FORCE, failing_restrict, &mut rep).is_err());
        assert_eq!(fs::read(&f).expect("after"), before);
        assert_eq!(dir_names(&dir), vec![String::from("k.env")]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn unix_file_is_0600_and_symlink_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tmp("unix");
        let f = dir.join("k.env");
        gen_file(&f, OPTS).expect("gen");
        assert_eq!(
            fs::metadata(&f).expect("m").permissions().mode() & 0o777,
            0o600
        );
        let link = dir.join("link.env");
        std::os::unix::fs::symlink(&f, &link).expect("symlink");
        assert!(gen_file(&link, FORCE).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn windows_file_acl_is_owner_only() {
        let dir = tmp("acl");
        let f = dir.join("k.env");
        gen_file(&f, OPTS).expect("gen");
        let out = std::process::Command::new("icacls")
            .arg(&f)
            .output()
            .expect("icacls");
        let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
        for banned in ["everyone", "builtin\\users", "authenticated users"] {
            assert!(!text.contains(banned), "{text}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_non_ignored_path_inside_the_repo() {
        let root = crate::gates::repo_root().expect("root");
        let f = root
            .join("xtask")
            .join("provision-test-must-not-exist.keys.env");
        let e = gen_file(&f, OPTS).expect_err("tracked path");
        assert!(e.to_string().contains("NOT gitignored"), "{e}");
        assert!(!f.exists());
        let ok = root.join(".dev").join("provision-ignored-check.keys.env");
        ensure_not_committable(&ok, false, &mut Vec::new()).expect(".dev is gitignored");
    }

    #[test]
    fn env_and_argument_refusals() {
        assert!(file_env("production").is_err());
        assert!(file_env("dev").is_err());
        assert!(file_env("staging").is_ok());
        assert!(run(["--bogus".to_owned()].into_iter()).is_err());
        assert!(run(["--env".to_owned(), "production".to_owned()].into_iter()).is_err());
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        let base = [
            "--keys-file",
            "k.env",
            "--approver",
            "0190a000-0000-7000-8000-000000000001",
            "--owner-approval-ref",
            "OWNER-1",
        ];
        let mut ok = s(&base);
        ok.extend(s(&["--db-url-env", "DSECURE_STAGING_ADMIN_URL"]));
        let a = SeedArgs::parse(&ok).expect("valid");
        assert_eq!(a.env, Environment::Staging);
        assert_eq!(a.tls_ca_env, "DB_TLS_CA");
        for bad in ["mysql://u:p@h:4000/x", "lower_case", "", "A-B", "1ABC"] {
            let mut v = s(&base);
            v.extend([String::from("--db-url-env"), bad.to_owned()]);
            assert!(SeedArgs::parse(&v).is_err(), "accepted `{bad}`");
        }
        let mut v = s(&base);
        v.extend(s(&["--db-url", "mysql://u:p@h/x"]));
        assert!(SeedArgs::parse(&v).is_err());
        let mut v = s(&base);
        v.extend(s(&["--db-url-env", "X", "--env", "production"]));
        assert!(SeedArgs::parse(&v).is_err());
        assert!(
            SeedArgs::parse(&s(&["--db-url-env", "X"])).is_err(),
            "missing args"
        );
    }

    #[test]
    fn target_refusals() {
        let ca = SecretString::from(String::from("/etc/ssl/certs/ca-certificates.crt"));
        let stg = Environment::Staging;
        for url in [
            "mysql://u:p@h.example.com:4000/Cloud_Erase__App?ssl-mode=VERIFY_IDENTITY",
            "mysql://u:p@h.example.com:4000/cloud_erase__app?ssl-mode=VERIFY_IDENTITY",
            "mysql://u:p@h.example.com:4000/Cloud%5FErase__App?ssl-mode=VERIFY_IDENTITY",
            "mysql://u:p@h.example.com:4000/cloud_erase_copy?ssl-mode=VERIFY_IDENTITY",
        ] {
            assert!(check_target(url, stg, Some(&ca)).is_err(), "{url}");
        }
        let good = "mysql://u:p@h.example.com:4000/dsecure_rs_staging?ssl-mode=VERIFY_IDENTITY";
        assert!(check_target(good, stg, Some(&ca)).is_ok());
        assert!(check_target(good, stg, None).is_err(), "CA required");
        assert!(
            check_target(
                "mysql://u:p@h.example.com:4000/dsecure_rs_staging",
                stg,
                Some(&ca)
            )
            .is_err(),
            "TLS required"
        );
        assert!(
            check_target(good, Environment::Test, None).is_err(),
            "test = loopback only"
        );
        assert!(
            check_target(
                "mysql://u:p@127.0.0.1:3307/dsecure_t_x",
                Environment::Test,
                None
            )
            .is_ok()
        );
        assert_eq!(url_host("mysql://u:p@[::1]:3307/x"), "::1");
    }

    #[test]
    fn seed_cli_reads_url_only_from_the_named_env_var() {
        let dir = tmp("seedcli");
        let f = dir.join("k.env");
        gen_file(&f, OPTS).expect("gen");
        let mut rep = Vec::new();
        let a = SeedArgs {
            keys_file: f,
            db_url_env: "DSECURE_TEST_UNSET_URL".into(),
            tls_ca_env: "DB_TLS_CA".into(),
            approver: uuid::Uuid::now_v7(),
            owner_approval_ref: "OWNER-1".into(),
            env: Environment::Staging,
        };
        let e = seed_cli(&a, &Env::from_pairs::<_, String, String>([]), &mut rep)
            .expect_err("unset var");
        assert!(e.to_string().contains("DSECURE_TEST_UNSET_URL"), "{e}");
        let env = Env::from_pairs([(
            "DSECURE_TEST_UNSET_URL",
            "mysql://u:p@h.example.com:4000/Cloud_Erase__App?ssl-mode=VERIFY_IDENTITY",
        )]);
        let e = seed_cli(&a, &env, &mut rep).expect_err("legacy");
        assert!(e.to_string().contains("legacy"), "{e}");
        assert!(!e.to_string().contains("u:p@"), "URL leaked: {e}");
        let _ = fs::remove_dir_all(&dir);
    }

    // ---------- seed-db on a LOCAL MySQL scratch DB (never TiDB, never remote) ----------

    /// Scratch DB user prefix of this test (dropped afterwards; only names with this prefix).
    const PADM_PREFIX: &str = "dsecure_tp_";

    fn valid_padm_user(u: &str) -> bool {
        u.strip_prefix(PADM_PREFIX)
            .is_some_and(|h| h.len() == 16 && h.bytes().all(|b| b.is_ascii_hexdigit()))
    }

    /// `url` with user/password replaced (password = random hex, no escaping needed).
    fn with_user(url: &str, user: &str, pw: &str) -> String {
        let (scheme, rest) = url.split_once("://").unwrap_or(("mysql", url));
        let auth_end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (auth, tail) = rest.split_at(auth_end);
        let host = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
        format!("{scheme}://{user}:{pw}@{host}{tail}")
    }

    async fn count(db: &db::Db, table: &str) -> i64 {
        use sqlx::Row as _;
        let rows = db::testing::raw_fetch(db, &format!("SELECT COUNT(*) AS n FROM {table}"), &[])
            .await
            .expect("count");
        rows.first()
            .expect("row")
            .try_get::<i64, _>("n")
            .expect("n")
    }

    async fn counts(db: &db::Db) -> (i64, i64, i64) {
        (
            count(db, "signing_keys").await,
            count(db, "audit_events").await,
            count(db, "data_keys").await,
        )
    }

    async fn root_exec(root: &mut sqlx::mysql::MySqlConnection, sql: String) {
        crate::gates::scratch::exec(root, sql)
            .await
            .expect("root exec");
    }

    async fn make_superadmin(mig: &db::Db) -> UserId {
        let sa = UserId(uuid::Uuid::now_v7());
        let mut bidx = [0u8; 32];
        bidx[..16].copy_from_slice(sa.0.as_bytes());
        let mut itx = mig.identity_tx().await.expect("itx");
        db::repo::users::insert(
            &mut itx,
            &db::repo::users::NewUser {
                id: sa,
                email_bidx: bidx,
                email_enc: vec![1, 2, 3],
                name_enc: None,
                status: db::repo::users::UserStatus::Active,
            },
            now_micros(),
        )
        .await
        .expect("user");
        itx.commit().await.expect("c");
        let mut boot =
            audit_row("staff.bootstrap", serde_json::json!({}), now_micros()).expect("audit");
        boot.actor_id = Some(sa.0);
        boot.row_hash = audit::chain::compute_row_hash(&boot).expect("h").to_vec();
        PlatformAdminDb::for_tests(mig.clone())
            .bootstrap_first_superadmin(sa, &boot, now_micros())
            .await
            .expect("bootstrap superadmin");
        sa
    }

    /// One platform DEK wrapped by `keys`' KEK (simulates a failed earlier run with another KEK file).
    async fn preseed_one_dek(mig: &db::Db, keys: &KeysFile) {
        let p = EnvKeyProvider::new(
            &keys.kek_id,
            [(keys.kek_id.clone(), (*keys.kek_b64).clone())],
        )
        .expect("p");
        let kid = crypto::Kid::generate(KeyPurpose::Secrets, None).expect("kid");
        let dek = crypto::Dek::generate().expect("dek");
        let w = p
            .wrap(
                &dek,
                &WrapContext {
                    kid: &kid,
                    purpose: KeyPurpose::Secrets,
                    tenant: None,
                },
            )
            .await
            .expect("wrap");
        DbDekStore::new(mig.clone())
            .insert(&kid, KeyPurpose::Secrets, None, &w)
            .await
            .expect("insert dek");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines)]
    async fn seed_db_on_local_scratch_as_platform_admin_user() {
        use db::grants::{DbRole, grant_statements};
        use db::testing::{ScratchDb, TestEngine};
        use sqlx::Row as _;
        if db::testing::test_engine() == TestEngine::TiDb {
            eprintln!("SKIP seed_db: local MySQL only (DSECURE_TEST_ENGINE=tidb)");
            return;
        }
        let env = match db::testing::load_env() {
            Ok(e) if e.root_password.is_some() => e,
            Ok(_) if db::testing::skip_allowed() => {
                eprintln!("SKIP seed_db: LOCAL_MYSQL_ROOT_PASSWORD missing");
                return;
            }
            Ok(_) => panic!("seed_db test needs LOCAL_MYSQL_ROOT_PASSWORD in the local env file"),
            Err(r) if db::testing::skip_allowed() => {
                eprintln!("SKIP seed_db: {r}");
                return;
            }
            Err(r) => panic!("local test DB env unavailable: {r}"),
        };
        let test_url = env.test_url.expose_secret().to_owned();
        assert!(
            matches!(
                url_host(&test_url).as_str(),
                "127.0.0.1" | "localhost" | "::1"
            ),
            "test DB must be local"
        );
        let scratch = ScratchDb::create(&env).await.expect("scratch");
        let name = scratch.name().to_owned();
        let mig = scratch.migrator().clone();
        let app = scratch.app().cloned();

        // Scratch user with ONLY the generated platform-admin grants (docs/ops/db_users.sql 4b).
        let mut root = db::testing::root_connection(&env, &name)
            .await
            .expect("root (local only)");
        let who: String = sqlx::raw_sql(sqlx::AssertSqlSafe(String::from("SELECT USER() AS u")))
            .fetch_one(&mut root)
            .await
            .expect("user()")
            .try_get("u")
            .expect("u");
        let host = who
            .rsplit_once('@')
            .map_or("localhost", |(_, h)| h)
            .to_owned();
        assert!(matches!(
            host.as_str(),
            "localhost" | "127.0.0.1" | "::1" | "%"
        ));
        let user = format!(
            "{PADM_PREFIX}{}",
            &uuid::Uuid::now_v7().simple().to_string()[16..]
        );
        assert!(valid_padm_user(&user));
        let grantee = format!("'{user}'@'{host}'");
        let pw = uuid::Uuid::now_v7().simple().to_string(); // random hex, never printed
        root_exec(
            &mut root,
            format!("CREATE USER {grantee} IDENTIFIED BY '{pw}'"),
        )
        .await;
        for g in grant_statements(DbRole::PlatformAdmin, &name, &grantee) {
            root_exec(&mut root, g).await;
        }
        let padm_url = SecretString::from(with_user(
            &db::testing::with_database(&test_url, &name),
            &user,
            &pw,
        ));

        let r = futures_util::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(async {
            let dir = tmp("seed");
            fs::create_dir_all(&dir).expect("mkdir");
            let ka = gen_file(&dir.join("a.env"), OPTS).expect("a");
            let kb = gen_file(&dir.join("b.env"), OPTS).expect("b");
            let keys = parse_keys_file(&fs::read_to_string(&ka.path).expect("r")).expect("a");
            let other = parse_keys_file(&fs::read_to_string(&kb.path).expect("r")).expect("b");
            let mut rep = Vec::new();
            let t = Environment::Test;

            // 1) Not staff: refused, nothing written (no DEKs, no audit, no keys).
            let c0 = counts(&mig).await;
            let nobody = UserId(uuid::Uuid::now_v7());
            let e = seed(
                padm_url.clone(),
                None,
                t,
                &keys,
                nobody,
                "OWNER-1",
                &mut rep,
            )
            .await
            .expect_err("non-staff approver");
            assert!(e.to_string().contains("approver"), "{e:#}");
            assert_eq!(counts(&mig).await, c0, "non-staff run wrote rows");
            assert_eq!(c0.2, 0);

            let sa = make_superadmin(&mig).await;

            // 2) Missing owner approval reference: refused, nothing written.
            let c1 = counts(&mig).await;
            assert!(
                seed(padm_url.clone(), None, t, &keys, sa, " ", &mut rep)
                    .await
                    .is_err()
            );
            assert_eq!(counts(&mig).await, c1);

            // 3) F1: one DEK already wrapped by KEK A; seeding with KEK B is refused, data_keys unchanged.
            preseed_one_dek(&mig, &keys).await;
            let c2 = counts(&mig).await;
            assert_eq!(c2.2, 1);
            let e = seed(padm_url.clone(), None, t, &other, sa, "OWNER-1", &mut rep)
                .await
                .expect_err("other KEK");
            assert!(e.to_string().contains("another KEK"), "{e:#}");
            assert_eq!(counts(&mig).await, c2, "wrong-KEK run wrote rows");

            // 4) Success with KEK A, as the platform-admin user: creates only the missing DEKs.
            let mut rep = Vec::new();
            let out = seed(padm_url.clone(), None, t, &keys, sa, "OWNER-1", &mut rep)
                .await
                .expect("seed");
            assert_eq!(out.deks_created, KeyPurpose::PLATFORM.len() - 1);
            let c3 = counts(&mig).await;
            assert_eq!(c3.0, c2.0 + 3, "3 signing keys");
            assert_eq!(c3.1, c2.1 + 1, "exactly one audit row (one commit)");
            assert_eq!(c3.2, i64::try_from(KeyPurpose::PLATFORM.len()).expect("n"));
            let report = String::from_utf8(rep).expect("utf8");
            assert!(report.contains(&keys.member_kid));
            assert!(!report.contains(keys.kek_b64.as_str()));

            // Audit row: system row of the ops CLI, claimed approver in metadata, no actor_id.
            let rows = db::testing::raw_fetch(
                &mig,
                "SELECT actor_kind, actor_id, CAST(metadata AS CHAR) AS m FROM audit_events \
                 WHERE action = 'keys.provision'",
                &[],
            )
            .await
            .expect("audit rows");
            assert_eq!(rows.len(), 1);
            let r = &rows[0];
            assert_eq!(r.try_get::<String, _>("actor_kind").expect("k"), "system");
            assert!(
                r.try_get::<Option<Vec<u8>>, _>("actor_id")
                    .expect("id")
                    .is_none()
            );
            let m: String = r.try_get("m").expect("m");
            let m: serde_json::Value = serde_json::from_str(&m).expect("json");
            assert_eq!(m["actor"], "ops_cli");
            assert_eq!(m["approver_proof"], "claimed");
            assert_eq!(m["claimed_approver"], sa.0.hyphenated().to_string());
            assert_eq!(m["owner_approval_ref"], "OWNER-1");
            assert_eq!(
                m["dek_kids_created"].as_array().map(Vec::len),
                Some(KeyPurpose::PLATFORM.len() - 1)
            );

            // App user loads what the api loads at startup.
            let reader = app.clone().unwrap_or_else(|| mig.clone());
            let provider: Arc<dyn KeyProvider> = Arc::new(
                EnvKeyProvider::new(
                    &keys.kek_id,
                    [(keys.kek_id.clone(), (*keys.kek_b64).clone())],
                )
                .expect("p"),
            );
            let ring = KeyRing::load_platform(provider, Arc::new(DbDekStore::new(reader.clone())))
                .await
                .expect("ring");
            let enc = AesGcmFieldEncryptor::new(Arc::new(ring));
            api::keys::load_jwt(&reader, &enc, &keys.member_kid, &keys.staff_kid)
                .await
                .expect("api load_jwt accepts seeded keys");
            let mut stx = reader.system_tx().await.expect("tx");
            let rk = signing_keys::by_kid(&mut stx, &out.report_kid)
                .await
                .expect("q")
                .expect("report key row");
            assert_eq!(rk.realm, SigningRealm::ReportCertificate);
            assert_eq!(rk.alg, SigAlg::Ed25519);
            let pk = rk.private_key(&enc).await.expect("decrypts");
            Ed25519Signer::from_pkcs8("r", &pk).expect("valid pkcs8");
            stx.rollback().await;

            // 5) Re-run with the same file: kid conflict, nothing written.
            let mut rep = Vec::new();
            assert!(
                seed(padm_url.clone(), None, t, &keys, sa, "OWNER-1", &mut rep)
                    .await
                    .is_err()
            );
            assert_eq!(counts(&mig).await, c3, "re-run wrote rows");
            // 6) Wrong approver after success: nothing written.
            assert!(
                seed(
                    padm_url.clone(),
                    None,
                    t,
                    &keys,
                    nobody,
                    "OWNER-1",
                    &mut rep
                )
                .await
                .is_err()
            );
            assert_eq!(counts(&mig).await, c3);
            // 7) Wrong KEK after success: nothing written.
            let e = seed(padm_url.clone(), None, t, &other, sa, "OWNER-1", &mut rep)
                .await
                .expect_err("other KEK");
            assert!(e.to_string().contains("another KEK"), "{e:#}");
            assert_eq!(counts(&mig).await, c3, "wrong-KEK run wrote rows");

            // 8) All DEKs already there (as after staff-bootstrap): same KEK, new kids -> 0 DEKs created,
            //    exactly 3 keys + 1 audit row.
            let again = KeysFile {
                kek_id: keys.kek_id.clone(),
                kek_b64: keys.kek_b64.clone(),
                member_kid: format!("jwt-member-staging-{}", rand_hex(8)),
                staff_kid: format!("jwt-staff-staging-{}", rand_hex(8)),
            };
            let out2 = seed(padm_url.clone(), None, t, &again, sa, "OWNER-2", &mut rep)
                .await
                .expect("seed with existing DEKs");
            assert_eq!(out2.deks_created, 0);
            assert_eq!(counts(&mig).await, (c3.0 + 3, c3.1 + 1, c3.2));
            let _ = fs::remove_dir_all(&dir);
        }))
        .await;
        if valid_padm_user(&user) {
            let _ =
                crate::gates::scratch::exec(&mut root, format!("DROP USER IF EXISTS {grantee}"))
                    .await;
        }
        let _ = sqlx::Connection::close(root).await;
        drop((mig, app));
        scratch.drop_db(&env).await.expect("drop scratch");
        if let Err(p) = r {
            std::panic::resume_unwind(p);
        }
    }
}
