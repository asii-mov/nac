use anyhow::{bail, Result};
use nac_appsec::{
    ArtifactStore, Assignment, Campaign, Controller, Id, Manifest, Runtime, RuntimeObservation,
    SqliteRepository, SystemClock,
};
use std::path::Path;

pub use super::appsec_doctor::{run_appsec_doctor, DoctorError};

pub struct AppsecControl {
    controller: Controller<SqliteRepository>,
}

impl AppsecControl {
    pub fn open(state: &Path) -> Result<Self> {
        let repository = SqliteRepository::open(state, 4)?;
        let artifacts = ArtifactStore::open(state)?;
        Ok(Self {
            controller: Controller::new(repository, artifacts, SystemClock),
        })
    }

    pub fn run(&self, manifest: Manifest) -> Result<Campaign> {
        let campaign = self.controller.create(manifest)?;
        let dispatch = self.controller.dispatch_next(
            campaign.id,
            campaign.revision,
            &mut NativeDispatchUnavailable,
        );
        if dispatch.is_ok() {
            bail!("native dispatch unexpectedly admitted work");
        }
        let result = self.controller.status(campaign.id)?;
        if result.dispatch_blocker.is_none() {
            dispatch?;
        }
        Ok(result)
    }

    pub fn status(&self, run: Id) -> Result<Campaign> {
        self.controller.status(run)
    }

    pub fn cancel(&self, run: Id, revision: u64) -> Result<Campaign> {
        self.controller.cancel(run, revision)
    }

    pub fn resume(&self, run: Id, revision: u64, task: Id, handoff: &str) -> Result<Campaign> {
        self.controller.resume(run, revision, task, handoff)
    }
}

struct NativeDispatchUnavailable;

impl Runtime for NativeDispatchUnavailable {
    fn check_capabilities(&self) -> Result<()> {
        bail!("native progress-watchdog integration, bounded operations and process-tree termination are not proved; tokens are observation-only and live execution is unavailable in this controller layer")
    }

    fn start(&mut self, _: &Assignment) -> Result<()> {
        self.check_capabilities()
    }

    fn observe(&mut self, _: Id) -> Result<RuntimeObservation> {
        bail!("native runtime reconciliation is not integrated")
    }

    fn cancel(&mut self, _: Id) -> Result<()> {
        self.check_capabilities()
    }

    fn diagnose(&mut self, _: Id) -> Result<nac_appsec::ArtifactRef> {
        bail!("native trusted diagnostic receipts are not integrated")
    }
}
