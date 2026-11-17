//! Deadline-aware CASE work. Diagnostics contain only node, closed stage/outcome and timing.

use std::{fmt, future::Future, time::Duration};

use anyhow::Result;
use tokio::time::{timeout_at, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectStage {
    Transport,
    Resume,
    Case,
    BusyWait,
    Rediscovery,
}

impl ConnectStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::Resume => "resume",
            Self::Case => "case",
            Self::BusyWait => "busy_wait",
            Self::Rediscovery => "rediscovery",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ConnectDeadline {
    pub stage: ConnectStage,
}

impl fmt::Display for ConnectDeadline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Matter connect deadline at {}", self.stage.as_str())
    }
}

impl std::error::Error for ConnectDeadline {}

/// The responder's minimum wait did not fit in this attempt's deadline.
/// A caller must not start another attempt before `retry_at`.
#[derive(Clone, Copy, Debug)]
pub struct ConnectBusy {
    pub retry_at: Instant,
}

impl ConnectBusy {
    pub fn retry_after(&self) -> Duration {
        self.retry_at.saturating_duration_since(Instant::now())
    }
}

impl fmt::Display for ConnectBusy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Matter responder BUSY; attempt deferred")
    }
}

impl std::error::Error for ConnectBusy {}

pub(crate) struct ConnectionBudget {
    node: u64,
    deadline: Option<Instant>,
}

impl ConnectionBudget {
    pub(crate) fn new(node: u64, deadline: Option<Instant>) -> Self {
        Self { node, deadline }
    }

    pub(crate) async fn run<T>(
        &self,
        stage: ConnectStage,
        work: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        let started = Instant::now();
        let result = match self.deadline {
            Some(deadline) if started >= deadline => Err(ConnectDeadline { stage }.into()),
            Some(deadline) => match timeout_at(deadline, work).await {
                // Tokio may poll a ready future before the expired timer. Do not
                // return late connection authority even when that future is ready.
                Ok(Ok(_)) if Instant::now() >= deadline => Err(ConnectDeadline { stage }.into()),
                Ok(result) => result,
                Err(_) => Err(ConnectDeadline { stage }.into()),
            },
            None => work.await,
        };
        let outcome = match &result {
            Ok(_) => "ok",
            Err(error) if error.is::<ConnectDeadline>() => "deadline",
            Err(error) if error.is::<crate::controller::SigmaBusy>() => "busy",
            Err(_) => "failed",
        };
        log::info!(
            "Matter connect stage node={} stage={} outcome={} elapsed_ms={}",
            self.node,
            stage.as_str(),
            outcome,
            started.elapsed().as_millis()
        );
        result
    }

    pub(crate) async fn busy_wait(&self, wait: Duration) -> Result<()> {
        let retry_at = Instant::now() + wait;
        if self.deadline.is_some_and(|deadline| retry_at >= deadline) {
            log::info!(
                "Matter connect stage node={} stage=busy_wait outcome=deferred wait_ms={}",
                self.node,
                wait.as_millis()
            );
            return Err(ConnectBusy { retry_at }.into());
        }
        self.run(ConnectStage::BusyWait, async {
            tokio::time::sleep_until(retry_at).await;
            Ok(())
        })
        .await
    }
}
