use thiserror::Error;
use tss_esapi::handles::PcrHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Digest, PcrSelectionList, PcrSlot};

#[derive(Error, Debug)]
pub enum PcrError {
    #[error("invalid bank")]
    InvalidBank,
    #[error("empty PCR selection list, expected at least on selection")]
    EmptyPcrSelectionList,
}

pub type Result<T, E = PcrError> = core::result::Result<T, E>;

pub fn pcr_slot_to_handle(slot: &PcrSlot) -> PcrHandle {
    match slot {
        PcrSlot::Slot0 => PcrHandle::Pcr0,
        PcrSlot::Slot1 => PcrHandle::Pcr1,
        PcrSlot::Slot2 => PcrHandle::Pcr2,
        PcrSlot::Slot3 => PcrHandle::Pcr3,
        PcrSlot::Slot4 => PcrHandle::Pcr4,
        PcrSlot::Slot5 => PcrHandle::Pcr5,
        PcrSlot::Slot6 => PcrHandle::Pcr6,
        PcrSlot::Slot7 => PcrHandle::Pcr7,
        PcrSlot::Slot8 => PcrHandle::Pcr8,
        PcrSlot::Slot9 => PcrHandle::Pcr9,
        PcrSlot::Slot10 => PcrHandle::Pcr10,
        PcrSlot::Slot11 => PcrHandle::Pcr11,
        PcrSlot::Slot12 => PcrHandle::Pcr12,
        PcrSlot::Slot13 => PcrHandle::Pcr13,
        PcrSlot::Slot14 => PcrHandle::Pcr14,
        PcrSlot::Slot15 => PcrHandle::Pcr15,
        PcrSlot::Slot16 => PcrHandle::Pcr16,
        PcrSlot::Slot17 => PcrHandle::Pcr17,
        PcrSlot::Slot18 => PcrHandle::Pcr18,
        PcrSlot::Slot19 => PcrHandle::Pcr19,
        PcrSlot::Slot20 => PcrHandle::Pcr20,
        PcrSlot::Slot21 => PcrHandle::Pcr21,
        PcrSlot::Slot22 => PcrHandle::Pcr22,
        PcrSlot::Slot23 => PcrHandle::Pcr23,
        PcrSlot::Slot24 => PcrHandle::Pcr24,
        PcrSlot::Slot25 => PcrHandle::Pcr25,
        PcrSlot::Slot26 => PcrHandle::Pcr26,
        PcrSlot::Slot27 => PcrHandle::Pcr27,
        PcrSlot::Slot28 => PcrHandle::Pcr28,
        PcrSlot::Slot29 => PcrHandle::Pcr29,
        PcrSlot::Slot30 => PcrHandle::Pcr30,
        PcrSlot::Slot31 => PcrHandle::Pcr31,
    }
}

pub struct PcrPolicyOptions {
    pub digest: Option<Digest>,
    pub pcr_selection_list: PcrSelectionList,
}

impl PcrPolicyOptions {
    pub fn with_digest(mut self, digest: Digest) -> Self {
        self.digest = Some(digest);
        self
    }
}

impl Default for PcrPolicyOptions {
    fn default() -> Self {
        let pcr_selection_list = PcrSelectionList::builder()
            .with_selection(
                HashingAlgorithm::Sha1,
                &[
                    PcrSlot::Slot0,
                    PcrSlot::Slot1,
                    PcrSlot::Slot2,
                    PcrSlot::Slot3,
                ],
            )
            .build()
            .unwrap();
        Self {
            digest: None,
            pcr_selection_list,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eyre::Result;

    #[test]
    fn testy() -> Result<()> {
        Ok(())
    }
}
