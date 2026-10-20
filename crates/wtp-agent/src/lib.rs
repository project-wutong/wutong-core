// SPDX-License-Identifier: AGPL-3.0-only
//! # wtp-agent
//!
//! Agent profile primitives. The [`TaskState`] machine follows WTP §9.2:
//!
//! ```text
//! created → assigned | cancelled
//! assigned → accepted | cancelled
//! accepted → running | cancelled
//! running → awaiting_approval | completed | failed | cancelled
//! awaiting_approval → running | completed | failed | cancelled
//! completed | failed | cancelled → (terminal)
//! ```
//!
//! [`TaskMachine`] adds the executor checks the spec requires on every transition: base
//! version (optimistic concurrency), actor authorization, a valid execution lease and
//! idempotency keys. Terminal states cannot be reversed; retries get new attempt ids.

use std::collections::HashMap;
pub use wtp_types::TaskState;
use wtp_types::{ErrorCode, WtpError, err};

/// Allowed successor states.
pub fn successors(s: TaskState) -> &'static [TaskState] {
    use TaskState::*;
    match s {
        Created => &[Assigned, Cancelled],
        Assigned => &[Accepted, Cancelled],
        Accepted => &[Running, Cancelled],
        Running => &[AwaitingApproval, Completed, Failed, Cancelled],
        AwaitingApproval => &[Running, Completed, Failed, Cancelled],
        Completed | Failed | Cancelled => &[],
    }
}

/// `true` for completed / failed / cancelled.
pub fn is_terminal(s: TaskState) -> bool {
    successors(s).is_empty()
}

/// Check a single transition (`ERR_PERMISSION` if illegal, like the reference).
pub fn check_transition(from: TaskState, to: TaskState) -> Result<(), WtpError> {
    if successors(from).contains(&to) {
        Ok(())
    } else {
        Err(err(
            ErrorCode::Permission,
            format!(
                "illegal task transition {} -> {}",
                from.as_str(),
                to.as_str()
            ),
        ))
    }
}

/// An execution lease held by the assignee while running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// Holder principal URN.
    pub holder: String,
    /// Expiry (Unix seconds).
    pub expires_at: i64,
}

/// A transition request.
#[derive(Debug, Clone)]
pub struct TransitionRequest<'a> {
    /// Principal requesting the transition.
    pub actor: &'a str,
    /// Target state.
    pub to: TaskState,
    /// Version the caller observed (optimistic concurrency).
    pub base_version: u64,
    /// Idempotency key; a retried identical request returns the recorded result.
    pub idempotency_key: &'a str,
    /// Current time (Unix seconds) for lease checks.
    pub now: i64,
}

/// Local task executor state (in-memory reference; persistence is the storage layer's job).
#[derive(Debug, Clone)]
pub struct TaskMachine {
    /// Current state.
    pub state: TaskState,
    /// Monotonic version, incremented on each applied transition.
    pub version: u64,
    /// Requester principal.
    pub requester: String,
    /// Assignee principal, once assigned.
    pub assignee: Option<String>,
    /// Lease required for running-side transitions.
    pub lease: Option<Lease>,
    /// Attempt counter (a retry after failure is a new task attempt id upstream).
    pub attempt: u32,
    applied: HashMap<String, (TaskState, u64)>,
}

impl TaskMachine {
    /// New task in `created`.
    pub fn new(requester: impl Into<String>) -> Self {
        Self {
            state: TaskState::Created,
            version: 0,
            requester: requester.into(),
            assignee: None,
            lease: None,
            attempt: 1,
            applied: HashMap::new(),
        }
    }

    /// Assign to an agent / principal (requester only).
    pub fn assign(
        &mut self,
        actor: &str,
        assignee: &str,
        base_version: u64,
        key: &str,
    ) -> Result<u64, WtpError> {
        self.assignee = Some(assignee.to_owned());
        let r = self.apply(TransitionRequest {
            actor,
            to: TaskState::Assigned,
            base_version,
            idempotency_key: key,
            now: 0,
        });
        if r.is_err() && self.state == TaskState::Created {
            self.assignee = None;
        }
        r
    }

    /// Grant an execution lease to the assignee.
    pub fn grant_lease(&mut self, holder: &str, expires_at: i64) -> Result<(), WtpError> {
        if self.assignee.as_deref() != Some(holder) {
            return Err(err(
                ErrorCode::Permission,
                "lease holder must be the assignee",
            ));
        }
        self.lease = Some(Lease {
            holder: holder.to_owned(),
            expires_at,
        });
        Ok(())
    }

    fn authorized(&self, actor: &str, to: TaskState) -> bool {
        use TaskState::*;
        let is_req = actor == self.requester;
        let is_asg = self.assignee.as_deref() == Some(actor);
        match to {
            Assigned => is_req,
            Cancelled => is_req || is_asg,
            Accepted | Running | AwaitingApproval | Failed => is_asg,
            // completion from awaiting_approval requires the requester (reviewer) to approve
            Completed => {
                if self.state == AwaitingApproval {
                    is_req
                } else {
                    is_asg
                }
            }
            Created => false,
        }
    }

    fn needs_lease(to: TaskState) -> bool {
        matches!(
            to,
            TaskState::Running | TaskState::AwaitingApproval | TaskState::Failed
        )
    }

    /// Apply a transition with all executor checks. Returns the new version.
    pub fn apply(&mut self, req: TransitionRequest<'_>) -> Result<u64, WtpError> {
        if let Some((to, ver)) = self.applied.get(req.idempotency_key) {
            return if *to == req.to {
                Ok(*ver)
            } else {
                Err(err(
                    ErrorCode::Replay,
                    "idempotency key reused for a different transition",
                ))
            };
        }
        if req.base_version != self.version {
            return Err(err(ErrorCode::Conflict, "stale task version"));
        }
        check_transition(self.state, req.to)?;
        if !self.authorized(req.actor, req.to) {
            return Err(err(
                ErrorCode::Permission,
                "actor not authorized for this transition",
            ));
        }
        if Self::needs_lease(req.to)
            || (req.to == TaskState::Completed && self.state == TaskState::Running)
        {
            match &self.lease {
                Some(l) if l.holder == req.actor && req.now < l.expires_at => {}
                _ => return Err(err(ErrorCode::Permission, "no valid execution lease")),
            }
        }
        self.state = req.to;
        self.version += 1;
        if is_terminal(self.state) {
            self.lease = None;
        }
        self.applied
            .insert(req.idempotency_key.to_owned(), (req.to, self.version));
        Ok(self.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use TaskState::*;

    const ALL: [TaskState; 8] = [
        Created,
        Assigned,
        Accepted,
        Running,
        AwaitingApproval,
        Completed,
        Failed,
        Cancelled,
    ];

    #[test]
    fn exhaustive_matrix_count() {
        let allowed = ALL
            .iter()
            .flat_map(|a| ALL.iter().map(move |b| (*a, *b)))
            .filter(|(a, b)| check_transition(*a, *b).is_ok())
            .count();
        assert_eq!(allowed, 2 + 2 + 2 + 4 + 4);
    }

    #[test]
    fn happy_path_with_guards() {
        let (req, agent) = ("urn:req", "urn:agent");
        let mut t = TaskMachine::new(req);
        assert_eq!(t.assign(req, agent, 0, "k1").unwrap(), 1);
        let step = |t: &mut TaskMachine, actor, to, v, k, now| {
            t.apply(TransitionRequest {
                actor,
                to,
                base_version: v,
                idempotency_key: k,
                now,
            })
        };
        step(&mut t, agent, Accepted, 1, "k2", 0).unwrap();
        // running needs a lease
        assert_eq!(
            step(&mut t, agent, Running, 2, "k3", 10).unwrap_err().code,
            ErrorCode::Permission
        );
        t.grant_lease(agent, 100).unwrap();
        step(&mut t, agent, Running, 2, "k3", 10).unwrap();
        // idempotent retry returns same version; stale version rejected
        assert_eq!(step(&mut t, agent, Running, 2, "k3", 10).unwrap(), 3);
        assert_eq!(
            step(&mut t, agent, AwaitingApproval, 2, "k4", 10)
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        step(&mut t, agent, AwaitingApproval, 3, "k4", 10).unwrap();
        // agent cannot self-approve
        assert_eq!(
            step(&mut t, agent, Completed, 4, "k5", 10)
                .unwrap_err()
                .code,
            ErrorCode::Permission
        );
        step(&mut t, req, Completed, 4, "k5", 10).unwrap();
        assert!(is_terminal(t.state));
        assert!(step(&mut t, req, Running, 5, "k6", 10).is_err());
    }

    #[test]
    fn expired_lease_rejected() {
        let mut t = TaskMachine::new("r");
        t.assign("r", "a", 0, "1").unwrap();
        t.apply(TransitionRequest {
            actor: "a",
            to: Accepted,
            base_version: 1,
            idempotency_key: "2",
            now: 0,
        })
        .unwrap();
        t.grant_lease("a", 5).unwrap();
        let e = t
            .apply(TransitionRequest {
                actor: "a",
                to: Running,
                base_version: 2,
                idempotency_key: "3",
                now: 5,
            })
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::Permission);
    }
}
