use crate::owner::OwnerVerdict;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbandonEvidence {
    pub lab_member: bool,
    pub owner: OwnerVerdict,
    pub grace_expired: bool,
    pub revalidated_now: bool,
}

pub fn proven(ev: &AbandonEvidence) -> bool {
    ev.lab_member
        && matches!(
            ev.owner,
            OwnerVerdict::Unclaimed | OwnerVerdict::ClaimedDown { .. }
        )
        && ev.grace_expired
        && ev.revalidated_now
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
}
