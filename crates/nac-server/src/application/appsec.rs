use anyhow::{Context, Result};
use nac_appsec::{
    ArtifactStore, Campaign, Controller, Id, Manifest, Runtime, SqliteRepository, SystemClock,
};
use std::path::Path;

pub use super::appsec_doctor::{run_appsec_doctor, DoctorError};
pub use super::appsec_runtime::{
    run_appsec_worker, supervise_appsec_worker, NacWorkerRuntime, NativeResearchModel,
};
pub use super::appsec_target::{
    AppsecTargetRunner, BuildDiagnosticProjection, BuildOutputStream, FrozenPilot,
    LocalPilotArtifacts, LocalPilotPreparation,
};

pub struct AppsecControl {
    controller: Controller<SqliteRepository>,
    state: std::path::PathBuf,
}

impl AppsecControl {
    pub fn open(state: &Path) -> Result<Self> {
        let repository = SqliteRepository::open(state, 4)?;
        let artifacts = ArtifactStore::open(state)?;
        Ok(Self {
            controller: Controller::new(repository, artifacts, SystemClock),
            state: state.to_path_buf(),
        })
    }

    pub fn open_with_target_capacity(state: &Path, target_capacity: u32) -> Result<Self> {
        let repository = SqliteRepository::open_with_target_capacity(state, 4, target_capacity)?;
        let artifacts = ArtifactStore::open(state)?;
        Ok(Self {
            controller: Controller::new(repository, artifacts, SystemClock),
            state: state.to_path_buf(),
        })
    }

    pub fn run(&self, manifest: Manifest) -> Result<Campaign> {
        if let Some(profile) = &manifest.experiments {
            let root = self.state.join("packages");
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            match std::fs::DirBuilder::new().mode(0o700).create(&root) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            let metadata = std::fs::symlink_metadata(&root)?;
            anyhow::ensure!(
                metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0,
                "package root must be an owner-only real directory"
            );
            let destination = root.join(&profile.package.manifest_sha256);
            if destination.exists() {
                profile.package.verify_export(&destination)?;
            } else {
                profile
                    .package
                    .export(&manifest.repositories, &destination)?;
            }
        }
        let mut runtime = super::appsec_runtime::NacWorkerRuntime::new(
            &self.state,
            std::env::current_exe()?,
            super::appsec_runtime::NativeResearchModel::default(),
        )?;
        runtime.inputs_ready = manifest.research.is_some();
        self.run_with_runtime(manifest, &mut runtime)
    }

    pub fn run_with_runtime(
        &self,
        manifest: Manifest,
        runtime: &mut impl Runtime,
    ) -> Result<Campaign> {
        let campaign = self.controller.create(manifest)?;
        let dispatch = self
            .controller
            .dispatch_next(campaign.id, campaign.revision, runtime);
        if self
            .controller
            .status(campaign.id)?
            .dispatch_blocker
            .is_none()
        {
            dispatch?;
        }
        self.controller.status(campaign.id)
    }

    pub fn tick(&self, run: Id, runtime: &mut impl Runtime) -> Result<Campaign> {
        let campaign = self.controller.reconcile(run, runtime)?;
        let occupied = campaign.occupied_attempts();
        let queued = campaign
            .tasks
            .iter()
            .any(|task| task.state == nac_appsec::ExecutionState::Queued);
        if campaign.cancelled || !queued || occupied >= campaign.manifest.max_concurrency as usize {
            return Ok(campaign);
        }
        self.controller
            .dispatch_next(run, campaign.revision, runtime)?;
        self.controller.status(run)
    }

    pub fn status(&self, run: Id) -> Result<Campaign> {
        self.controller.status(run)
    }

    pub fn cancel_experiment(&self, run: Id, experiment_id: Id) -> Result<nac_appsec::Experiment> {
        let campaign = self.controller.status(run)?;
        let experiment = campaign
            .experiments
            .iter()
            .find(|experiment| experiment.id == experiment_id)
            .context("experiment unavailable")?;
        let lease = campaign
            .tasks
            .iter()
            .find(|task| task.id == experiment.task_id)
            .and_then(|task| task.attempts.last())
            .map(|attempt| attempt.lease.clone())
            .context("experiment owner unavailable")?;
        self.controller.cancel_experiment(&lease, experiment_id)
    }

    pub fn recover_experiment(&self, run: Id, experiment_id: Id) -> Result<nac_appsec::Experiment> {
        let campaign = self.controller.status(run)?;
        let experiment = campaign
            .experiments
            .iter()
            .find(|experiment| experiment.id == experiment_id)
            .context("experiment unavailable")?;
        let lease = campaign
            .tasks
            .iter()
            .find(|task| task.id == experiment.task_id)
            .and_then(|task| task.attempts.last())
            .map(|attempt| attempt.lease.clone())
            .context("experiment owner unavailable")?;
        self.controller.recover_experiment(&lease, experiment_id)
    }

    pub fn reconcile_experiments(&self, run: Id) -> Result<Campaign> {
        self.controller
            .reconcile_experiments(run, &mut AppsecTargetRunner::new(&self.state)?)
    }

    pub fn cancel(&self, run: Id, revision: u64) -> Result<Campaign> {
        let campaign = self.controller.cancel(run, revision)?;
        let mut runtime = NacWorkerRuntime::new(
            &self.state,
            std::env::current_exe()?,
            NativeResearchModel::default(),
        )?;
        let mut first_error = None;
        for attempt in campaign
            .tasks
            .iter()
            .flat_map(|task| &task.attempts)
            .filter(|attempt| attempt.runtime_slot_held)
        {
            if let Err(error) = runtime.cancel(attempt.lease.attempt_id) {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error)
                .context("canonical cancellation recorded; runtime cleanup remains uncertain");
        }
        let campaign = self
            .controller
            .reconcile(run, &mut runtime)
            .context("canonical cancellation recorded; runtime cleanup remains uncertain")?;
        if campaign.occupied_targets() > 0 {
            self.controller
                .reconcile_experiments(run, &mut AppsecTargetRunner::new(&self.state)?)
        } else {
            Ok(campaign)
        }
    }

    pub fn recover(
        &self,
        run: Id,
        revision: u64,
        task: Id,
        runtime: &mut impl Runtime,
    ) -> Result<Campaign> {
        self.controller.recover(run, revision, task, runtime)
    }

    pub fn resume(&self, run: Id, revision: u64, task: Id, handoff: &str) -> Result<Campaign> {
        self.controller.resume(run, revision, task, handoff)
    }
}
