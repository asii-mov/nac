pub(crate) mod credentials;
pub(crate) mod delegation;
pub(crate) mod managed;
pub(crate) mod model_catalog;
pub(crate) mod model_configurations;
pub(crate) mod projects;
pub(crate) mod request_validation;
pub(crate) mod session_attachment;
pub(crate) mod session_configuration;
pub(crate) mod session_creation;
pub(crate) mod session_lifecycle;
pub(crate) mod session_runs;
pub(crate) mod session_terminals;
pub(crate) mod sessions;
pub(crate) mod ssh_configurations;
pub(crate) mod workspace;

/// Application-level tri-state update semantics. Delivery adapters map their
/// wire representation into this type before invoking a use case.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum Field<T> {
    #[default]
    Unchanged,
    Clear,
    Set(T),
}
pub(crate) mod appsec;
pub(crate) mod appsec_doctor;
pub(crate) mod appsec_remediation;
pub(crate) mod appsec_runtime;
pub(crate) mod appsec_target;
