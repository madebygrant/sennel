// The desktop reads the same config file as the terminal app, so both open the same library of
// vaults with the same timeouts. Only the keys a window uses are read here.

use std::path::PathBuf;

use sennel_core::config::{self, FileConfig, Generator};
use sennel_core::vault::YubiSpec;

#[derive(Clone, Debug)]
pub struct Settings {
    /// None in tests, which must not write anyone's config.
    pub config_file: Option<PathBuf>,
    pub db: Option<PathBuf>,
    pub recent: Vec<PathBuf>,
    pub clipboard_timeout: u64,
    pub lock_timeout: u64,
    pub backups: usize,
    pub backup_dir: PathBuf,
    pub yubikey: Option<YubiSpec>,
    pub ssh_agent: bool,
    pub ssh_lifetime: u32,
    pub touch_id: bool,
    pub single_keys: bool,
    pub generator: Generator,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            config_file: None,
            db: None,
            recent: Vec::new(),
            clipboard_timeout: config::DEFAULT_CLIPBOARD_TIMEOUT,
            lock_timeout: config::DEFAULT_LOCK_TIMEOUT,
            backups: 0,
            backup_dir: PathBuf::new(),
            yubikey: None,
            ssh_agent: false,
            ssh_lifetime: 3600,
            touch_id: false,
            single_keys: true,
            generator: Generator::default(),
        }
    }
}

impl Settings {
    // The same checks and defaults as the terminal app, from core, so one config file is accepted
    // or refused by both.
    pub fn load() -> Result<Self, String> {
        let path = config::config_path();
        let file = FileConfig::load(&path, false).map_err(|e| format!("{e:#}"))?;
        let fail = |e: anyhow::Error| format!("{e:#}");
        Ok(Settings {
            config_file: Some(path),
            db: file.db.as_deref().map(config::expand),
            recent: file
                .recent
                .unwrap_or_default()
                .iter()
                .map(|p| config::expand(p))
                .collect(),
            clipboard_timeout: file
                .clipboard_timeout
                .unwrap_or(config::DEFAULT_CLIPBOARD_TIMEOUT),
            lock_timeout: file.lock_timeout.unwrap_or(config::DEFAULT_LOCK_TIMEOUT),
            backups: config::backups(file.backups).map_err(fail)?,
            backup_dir: file
                .backup_dir
                .as_deref()
                .map_or_else(config::default_backup_dir, config::expand),
            yubikey: file.yubikey.as_deref().map(str::parse).transpose()?,
            ssh_agent: file.ssh_agent.unwrap_or(false),
            ssh_lifetime: config::lifetime(file.ssh_agent_lifetime).map_err(fail)?,
            touch_id: file.touch_id.unwrap_or(false) && cfg!(target_os = "macos"),
            single_keys: file.single_keys.unwrap_or(true),
            generator: config::generator(file.generator.as_ref()).map_err(fail)?,
        })
    }
}
