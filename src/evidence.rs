use crate::owner::OwnerVerdict;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientWorkState {
    Active {
        reason: String,
    },
    IdleVerified {
        surfaces: Vec<String>,
    },
    Unknown {
        missing: Vec<String>,
    },
    Error {
        note: String,
    },
    /// Codex-grade: zero work observed, but client presence remains unverified.
    WorkAbsent {
        note: String,
    },
}

pub fn client_work_to_fields(s: &ClientWorkState) -> (Option<bool>, Option<bool>) {
    match s {
        ClientWorkState::Active { .. } => (Some(false), Some(false)),
        ClientWorkState::IdleVerified { .. } => (Some(true), Some(true)),
        ClientWorkState::WorkAbsent { .. } => (None, Some(true)),
        ClientWorkState::Unknown { .. } | ClientWorkState::Error { .. } => (None, None),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbandonEvidence {
    pub lab_member: bool,
    pub owner: OwnerVerdict,
    pub grace_expired: bool,
    pub revalidated_now: bool,
    pub owner_dead: Option<bool>,
    pub last_client_gone: Option<bool>,
    pub no_pending_work: Option<bool>,
}

pub fn proven(ev: &AbandonEvidence) -> bool {
    ev.lab_member
        && matches!(
            ev.owner,
            OwnerVerdict::Unclaimed | OwnerVerdict::ClaimedDown { .. }
        )
        && ev.grace_expired
        && ev.revalidated_now
        && ev.owner_dead == Some(true)
        && ev.last_client_gone == Some(true)
        && ev.no_pending_work == Some(true)
}

pub fn positive_vs_absent(ev: &AbandonEvidence) -> Option<bool> {
    if !ev.lab_member || !ev.grace_expired || !ev.revalidated_now {
        None
    } else {
        match ev.owner {
            OwnerVerdict::ClaimedActive { .. } => Some(false),
            OwnerVerdict::ClaimedDown { .. } | OwnerVerdict::Unclaimed => Some(true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn evidence() -> AbandonEvidence {
        AbandonEvidence {
            lab_member: true,
            owner: OwnerVerdict::Unclaimed,
            grace_expired: true,
            revalidated_now: true,
            owner_dead: Some(true),
            last_client_gone: Some(true),
            no_pending_work: Some(true),
        }
    }
    #[test]
    fn every_required_piece_is_mandatory() {
        let e = evidence();
        assert!(proven(&e));
        let mut x = e.clone();
        x.lab_member = false;
        assert!(!proven(&x));
        let mut x = e.clone();
        x.owner_dead = None;
        assert!(!proven(&x));
        let mut x = e.clone();
        x.last_client_gone = None;
        assert!(!proven(&x));
        let mut x = e.clone();
        x.no_pending_work = None;
        assert!(!proven(&x));
        let mut x = e.clone();
        x.owner = OwnerVerdict::ClaimedActive {
            service: "x".into(),
        };
        assert!(!proven(&x));
        let mut x = e.clone();
        x.grace_expired = false;
        assert!(!proven(&x));
        let mut x = e;
        x.revalidated_now = false;
        assert!(!proven(&x));
    }
    #[test]
    fn absence_is_distinct_from_unknown() {
        let mut e = evidence();
        e.owner = OwnerVerdict::ClaimedActive {
            service: "x".into(),
        };
        assert_eq!(positive_vs_absent(&e), Some(false));
        e.owner = OwnerVerdict::Unclaimed;
        assert_eq!(positive_vs_absent(&e), Some(true));
        e.revalidated_now = false;
        assert_eq!(positive_vs_absent(&e), None);
    }

    #[test]
    fn client_rescue_during_grace_invalidates_proof() {
        let mut ev = evidence();
        assert!(proven(&ev));
        ev.owner = OwnerVerdict::ClaimedActive {
            service: "client".into(),
        };
        assert!(!proven(&ev));
    }

    #[test]
    fn client_work_states_map_conjunctively_and_rescue_invalidates() {
        let states = [
            (
                ClientWorkState::Active {
                    reason: "work".into(),
                },
                (Some(false), Some(false)),
            ),
            (
                ClientWorkState::IdleVerified {
                    surfaces: vec!["session".into()],
                },
                (Some(true), Some(true)),
            ),
            (
                ClientWorkState::Unknown {
                    missing: vec!["clients".into()],
                },
                (None, None),
            ),
            (
                ClientWorkState::Error {
                    note: "probe failed".into(),
                },
                (None, None),
            ),
            (
                ClientWorkState::WorkAbsent {
                    note: "no active work".into(),
                },
                (None, Some(true)),
            ),
        ];
        for (state, expected) in states {
            assert_eq!(client_work_to_fields(&state), expected);
        }
        for state in [
            ClientWorkState::Unknown { missing: vec![] },
            ClientWorkState::Error {
                note: String::new(),
            },
            ClientWorkState::WorkAbsent {
                note: "zero work, clients unknown".into(),
            },
        ] {
            let (last_client_gone, no_pending_work) = client_work_to_fields(&state);
            let mut ev = evidence();
            ev.last_client_gone = last_client_gone;
            ev.no_pending_work = no_pending_work;
            assert!(!proven(&ev));
        }
        let (last_client_gone, no_pending_work) = client_work_to_fields(&states_idle());
        let mut ev = evidence();
        ev.last_client_gone = last_client_gone;
        ev.no_pending_work = no_pending_work;
        assert!(proven(&ev));
        let (last_client_gone, no_pending_work) = client_work_to_fields(&ClientWorkState::Active {
            reason: "rescue".into(),
        });
        ev.last_client_gone = last_client_gone;
        ev.no_pending_work = no_pending_work;
        assert!(!proven(&ev));
    }

    fn states_idle() -> ClientWorkState {
        ClientWorkState::IdleVerified { surfaces: vec![] }
    }
}
