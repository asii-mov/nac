use anyhow::{Context, Result};
use nac_appsec::{
    ArtifactStore, Campaign, Controller, Id, Manifest, Runtime, SqliteRepository, SystemClock,
};
use std::path::Path;

pub use super::appsec_doctor::{run_appsec_doctor, DoctorError};
pub use super::appsec_runtime::{
    run_appsec_worker, supervise_appsec_worker, NacWorkerRuntime, NativeResearchModel,
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

    pub fn run(&self, manifest: Manifest) -> Result<Campaign> {
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
        let occupied = campaign
            .tasks
            .iter()
            .flat_map(|task| &task.attempts)
            .filter(|attempt| attempt.runtime_slot_held)
            .count();
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
        self.controller
            .reconcile(run, &mut runtime)
            .context("canonical cancellation recorded; runtime cleanup remains uncertain")
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
