//! Distinct patch-author profile for the Go authorization remediation pilot.
//!
//! `generator` implements `nac_appsec::PatchGenerator` behind a
//! `nac_core::controlled_coding::ControlledCodingFacade`: the model touches
//! only exact frozen source bytes through a scoped read/search/edit/format/
//! check tool surface, never a controller artifact browser, validator
//! records, evaluator registry, network tool, delegation tool, or live
//! checkout. A sibling `evaluator` module (added separately) owns the
//! independent paired evaluation profile; the two share this directory but
//! not any file.

pub(crate) mod generator;
