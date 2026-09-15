use crate::tools::ThreadCancellation;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerOperation {
    pub id: String,
    pub kind: String,
    pub started_ms: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WorkerControlSnapshot {
    pub active: BTreeMap<String, WorkerOperation>,
    pub observed_tokens: Option<u64>,
    pub observed_output_bytes: Option<u64>,
    pub usage_incomplete: bool,
}

#[derive(Clone)]
pub struct ManagedWorkerControl {
    state: Arc<Mutex<WorkerControlSnapshot>>,
    cancellation: ThreadCancellation,
    wall: Duration,
    output_bytes: usize,
}

impl ManagedWorkerControl {
    pub fn new(wall: Duration, output_bytes: usize) -> Result<Self> {
        ensure!(
            !wall.is_zero() && output_bytes > 0,
            "worker operations require positive bounds"
        );
        Ok(Self {
            state: Arc::default(),
            cancellation: ThreadCancellation::default(),
            wall,
            output_bytes,
        })
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    pub fn snapshot(&self) -> WorkerControlSnapshot {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn record_usage(&self, usage: Option<&crate::model::TokenUsage>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(usage) = usage {
            state.observed_tokens = state
                .observed_tokens
                .unwrap_or(0)
                .checked_add(usage.input_tokens)
                .and_then(|v| v.checked_add(usage.output_tokens));
            if state.observed_tokens.is_none() {
                state.usage_incomplete = true;
            }
        } else {
            state.usage_incomplete = true;
        }
    }

    pub(crate) fn check_output(&self, bytes: usize) -> Result<()> {
        ensure!(
            bytes <= self.output_bytes,
            "worker operation response exceeds output bound"
        );
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.observed_output_bytes = state
            .observed_output_bytes
            .unwrap_or(0)
            .checked_add(bytes as u64);
        Ok(())
    }

    pub(crate) async fn bounded<T>(
        &self,
        kind: &str,
        operation: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        ensure!(
            !self.cancellation.is_cancelled(),
            "controlled worker cancelled"
        );
        let id = uuid::Uuid::new_v4().to_string();
        let started_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?;
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
            .insert(
                id.clone(),
                WorkerOperation {
                    id: id.clone(),
                    kind: kind.to_string(),
                    started_ms,
                },
            );
        let guard = OperationGuard {
            control: self.clone(),
            id,
            model: kind == "model",
            finished: false,
        };
        let result = tokio::select! {
            biased;
            () = self.cancelled() => Err(anyhow::anyhow!("controlled worker cancelled")),
            result = tokio::time::timeout(self.wall, operation) => result.map_err(|_| anyhow::anyhow!("worker operation timed out")).and_then(|result| result),
        };
        let mut guard = guard;
        guard.finished = result.is_ok();
        result
    }
}

struct OperationGuard {
    control: ManagedWorkerControl,
    id: String,
    model: bool,
    finished: bool,
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        let mut state = self
            .control
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active.remove(&self.id);
        if self.model && !self.finished {
            state.usage_incomplete = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parallel_operations_keep_original_identity_until_each_finishes() {
        let control = ManagedWorkerControl::new(Duration::from_secs(5), 100).unwrap();
        let (first_send, first_receive) = tokio::sync::oneshot::channel::<()>();
        let first_control = control.clone();
        let first = tokio::spawn(async move {
            first_control
                .bounded("tool", async {
                    first_receive.await?;
                    Ok(())
                })
                .await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let initial = control.snapshot().active.values().next().unwrap().clone();
        let (second_send, second_receive) = tokio::sync::oneshot::channel::<()>();
        let second_control = control.clone();
        let second = tokio::spawn(async move {
            second_control
                .bounded("tool", async {
                    second_receive.await?;
                    Ok(())
                })
                .await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let snapshot = control.snapshot();
        assert_eq!(snapshot.active.len(), 2);
        assert_eq!(snapshot.active[&initial.id].started_ms, initial.started_ms);
        first_send.send(()).unwrap();
        first.await.unwrap().unwrap();
        assert_eq!(control.snapshot().active.len(), 1);
        assert!(!control.snapshot().active.contains_key(&initial.id));
        second_send.send(()).unwrap();
        second.await.unwrap().unwrap();
        assert!(control.snapshot().active.is_empty());
    }

    #[tokio::test]
    async fn cancellation_interrupts_opaque_await_and_never_reports_zero_usage() {
        let control = ManagedWorkerControl::new(Duration::from_secs(5), 100).unwrap();
        let running = control.clone();
        let task =
            tokio::spawn(
                async move { running.bounded::<()>("model", std::future::pending()).await },
            );
        tokio::time::sleep(Duration::from_millis(10)).await;
        control.cancel();
        assert!(task.await.unwrap().is_err());
        assert!(control.snapshot().usage_incomplete);
        assert_eq!(control.snapshot().observed_tokens, None);
        assert!(control.snapshot().active.is_empty());
    }
}
