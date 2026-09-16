use crate::{artifacts::private_directory, require_version, Campaign, Id, Result};
use anyhow::ensure;
use cap_std::fs::{Dir, OpenOptions, OpenOptionsExt};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{path::Path, sync::Mutex, time::Duration};

pub trait Repository: Send + Sync {
    fn insert(&self, campaign: &Campaign) -> Result<()>;
    fn read(&self, run: Id) -> Result<Campaign>;
    fn update(
        &self,
        run: Id,
        expected_revision: Option<u64>,
        operation: &mut dyn FnMut(&mut Campaign, u32) -> Result<()>,
    ) -> Result<Campaign>;
}

pub struct SqliteRepository {
    connection: Mutex<Connection>,
    _directory: Dir,
}

impl SqliteRepository {
    pub fn open(path: &Path, host_capacity: u32) -> Result<Self> {
        Self::open_configured(path, host_capacity, None)
    }

    pub fn open_with_target_capacity(
        path: &Path,
        host_capacity: u32,
        target_capacity: u32,
    ) -> Result<Self> {
        ensure!(
            (1..=32).contains(&target_capacity),
            "target capacity must be between one and 32"
        );
        Self::open_configured(path, host_capacity, Some(target_capacity))
    }

    fn open_configured(
        path: &Path,
        host_capacity: u32,
        target_capacity: Option<u32>,
    ) -> Result<Self> {
        ensure!(
            (1..=4).contains(&host_capacity),
            "host capacity must be between one and four"
        );
        let directory = private_directory(path)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = directory.open_with("control.sqlite", &options)?;
        ensure!(
            file.metadata()?.is_file(),
            "control database is not a regular file"
        );
        let connection = Connection::open_with_flags(
            path.join("control.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(Duration::from_secs(10))?;
        connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS target_settings (singleton INTEGER PRIMARY KEY CHECK(singleton=1), capacity INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS settings (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL, host_capacity INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS campaigns (id TEXT PRIMARY KEY, revision INTEGER NOT NULL, record TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS accepted_keys (run_id TEXT NOT NULL, task_id TEXT NOT NULL, submission_key TEXT NOT NULL, payload_hash TEXT NOT NULL, accepted_id TEXT NOT NULL UNIQUE, PRIMARY KEY(run_id, task_id, submission_key));")?;
        connection.execute(
            "INSERT OR IGNORE INTO settings VALUES (1, 1, ?1)",
            [host_capacity],
        )?;
        let (version, capacity): (u32, u32) = connection.query_row(
            "SELECT schema_version, host_capacity FROM settings",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        require_version(version)?;
        ensure!(
            capacity == host_capacity,
            "host capacity differs from the persisted controller configuration"
        );
        if let Some(target_capacity) = target_capacity {
            connection.execute(
                "INSERT OR IGNORE INTO target_settings VALUES (1, ?1)",
                [target_capacity],
            )?;
            let configured: u32 =
                connection
                    .query_row("SELECT capacity FROM target_settings", [], |row| row.get(0))?;
            ensure!(
                configured == target_capacity,
                "target capacity differs from persisted configuration"
            );
        }
        Ok(Self {
            connection: Mutex::new(connection),
            _directory: directory,
        })
    }
}

impl Repository for SqliteRepository {
    fn insert(&self, campaign: &Campaign) -> Result<()> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("repository lock poisoned"))?;
        connection.execute(
            "INSERT INTO campaigns (id, revision, record) VALUES (?1, ?2, ?3)",
            params![
                campaign.id.to_string(),
                campaign.revision,
                serde_json::to_string(campaign)?
            ],
        )?;
        Ok(())
    }

    fn read(&self, run: Id) -> Result<Campaign> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("repository lock poisoned"))?;
        read_campaign(&connection, run)
    }

    fn update(
        &self,
        run: Id,
        expected_revision: Option<u64>,
        operation: &mut dyn FnMut(&mut Campaign, u32) -> Result<()>,
    ) -> Result<Campaign> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("repository lock poisoned"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut campaign = read_campaign(&tx, run)?;
        let revision = campaign.revision;
        if let Some(expected) = expected_revision {
            ensure!(
                revision == expected,
                "revision conflict: expected {expected}, current {revision}"
            );
        }
        let capacity: u32 =
            tx.query_row("SELECT host_capacity FROM settings", [], |row| row.get(0))?;
        let mut occupied: u32 = 0;
        let mut targets = 0usize;
        {
            let mut query = tx.prepare("SELECT record FROM campaigns WHERE id != ?1")?;
            for row in query.query_map([run.to_string()], |row| row.get::<_, String>(0))? {
                let other: Campaign = serde_json::from_str(&row?)?;
                require_version(other.schema_version)?;
                occupied = occupied
                    .checked_add(slots(&other))
                    .ok_or_else(|| anyhow::anyhow!("slot overflow"))?;
                targets = targets
                    .checked_add(other.occupied_targets())
                    .ok_or_else(|| anyhow::anyhow!("target count overflow"))?;
            }
        }
        operation(&mut campaign, capacity.saturating_sub(occupied))?;
        campaign.fence_experiments(campaign.updated_ms);
        let target_capacity: usize = tx
            .query_row("SELECT capacity FROM target_settings", [], |row| row.get(0))
            .optional()?
            .unwrap_or(0);
        ensure!(
            targets
                .checked_add(campaign.occupied_targets())
                .is_some_and(|count| count <= target_capacity),
            "host target capacity exhausted or not configured"
        );
        for accepted in &campaign.accepted {
            let key = (run.to_string(), accepted.task_id.to_string(), &accepted.key);
            tx.execute(
                "INSERT OR IGNORE INTO accepted_keys VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    key.0,
                    key.1,
                    key.2,
                    accepted.payload_hash,
                    accepted.id.to_string()
                ],
            )?;
            let existing: (String, String) = tx.query_row("SELECT payload_hash, accepted_id FROM accepted_keys WHERE run_id=?1 AND task_id=?2 AND submission_key=?3", params![key.0, key.1, key.2], |row| Ok((row.get(0)?, row.get(1)?)))?;
            ensure!(
                existing == (accepted.payload_hash.clone(), accepted.id.to_string()),
                "database submission uniqueness conflict"
            );
        }
        ensure!(
            campaign.id == run && campaign.revision == revision,
            "repository identity/revision mutation is forbidden"
        );
        campaign.revision = revision
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("revision overflow"))?;
        let changed = tx.execute(
            "UPDATE campaigns SET revision=?1, record=?2 WHERE id=?3 AND revision=?4",
            params![
                campaign.revision,
                serde_json::to_string(&campaign)?,
                run.to_string(),
                revision
            ],
        )?;
        ensure!(changed == 1, "revision conflict");
        tx.commit()?;
        Ok(campaign)
    }
}

pub(crate) fn slots(campaign: &Campaign) -> u32 {
    campaign.occupied_attempts().try_into().unwrap_or(u32::MAX)
}

fn read_campaign(connection: &Connection, run: Id) -> Result<Campaign> {
    let row: Option<(u64, String)> = connection
        .query_row(
            "SELECT revision, record FROM campaigns WHERE id=?1",
            [run.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (revision, record) = row.ok_or_else(|| anyhow::anyhow!("unknown campaign"))?;
    let mut campaign: Campaign = serde_json::from_str(&record)?;
    require_version(campaign.schema_version)?;
    ensure!(
        campaign.id == run && campaign.revision == revision,
        "corrupt campaign identity or revision"
    );
    if campaign
        .workflow
        .as_ref()
        .is_some_and(|workflow| workflow.complete && !workflow.completion_supported(&campaign))
    {
        if let Some(workflow) = &mut campaign.workflow {
            workflow.complete = false;
        }
    }
    Ok(campaign)
}
