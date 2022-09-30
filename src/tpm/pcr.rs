use num_traits::cast::FromPrimitive;
use thiserror::Error;
use tss_esapi::handles::PcrHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Digest, PcrSelectionList, PcrSlot};

#[derive(Error, Debug, PartialEq)]
pub enum PcrError {
    #[error("invalid bank")]
    InvalidBank,
    #[error("empty PCR selection list, expected at least on selection")]
    EmptyPcrSelectionList,
    #[error("invalid PCR selection list specification `{0}`")]
    InvalidPcrSelectionString(String),
    #[error("invalid PCR bank `{0}`")]
    InvalidPcrBank(String),
    #[error("invalid PCR slot `{0}`")]
    InvalidPcrSlot(String),
    #[error(transparent)]
    TssEsapi(#[from] tss_esapi::Error),
}

pub type Result<T, E = PcrError> = core::result::Result<T, E>;

fn parse_pcr_bank(bank: &str) -> Result<HashingAlgorithm> {
    match bank {
        "sha1" => Ok(HashingAlgorithm::Sha1),
        _ => Err(PcrError::InvalidPcrBank(bank.to_string())),
    }
}

fn parse_slot(slot: &str) -> Result<PcrSlot> {
    match slot {
        "0" => Ok(PcrSlot::Slot0),
        "1" => Ok(PcrSlot::Slot1),
        "2" => Ok(PcrSlot::Slot2),
        "3" => Ok(PcrSlot::Slot3),
        "4" => Ok(PcrSlot::Slot4),
        "5" => Ok(PcrSlot::Slot5),
        "6" => Ok(PcrSlot::Slot6),
        "7" => Ok(PcrSlot::Slot7),
        "8" => Ok(PcrSlot::Slot8),
        "9" => Ok(PcrSlot::Slot9),
        "10" => Ok(PcrSlot::Slot10),
        "11" => Ok(PcrSlot::Slot11),
        "12" => Ok(PcrSlot::Slot12),
        "13" => Ok(PcrSlot::Slot13),
        "14" => Ok(PcrSlot::Slot14),
        "15" => Ok(PcrSlot::Slot15),
        "16" => Ok(PcrSlot::Slot16),
        "17" => Ok(PcrSlot::Slot17),
        "18" => Ok(PcrSlot::Slot18),
        "19" => Ok(PcrSlot::Slot19),
        "20" => Ok(PcrSlot::Slot20),
        "21" => Ok(PcrSlot::Slot21),
        "22" => Ok(PcrSlot::Slot22),
        "23" => Ok(PcrSlot::Slot23),
        "24" => Ok(PcrSlot::Slot24),
        "25" => Ok(PcrSlot::Slot25),
        "26" => Ok(PcrSlot::Slot26),
        "27" => Ok(PcrSlot::Slot27),
        "28" => Ok(PcrSlot::Slot28),
        "29" => Ok(PcrSlot::Slot29),
        "30" => Ok(PcrSlot::Slot30),
        "31" => Ok(PcrSlot::Slot31),
        _ => Err(PcrError::InvalidPcrSlot(slot.to_string())),
    }
}

fn parse_slots(slots: &str) -> Result<Vec<PcrSlot>> {
    slots.split(',').map(parse_slot).collect()
}

pub fn parse_pcr_selection_list(expression: &str) -> Result<PcrSelectionList> {
    let (bank, slots) = expression
        .split_once(':')
        .ok_or_else(|| PcrError::InvalidPcrSelectionString(expression.to_owned()))?;
    let hash_algorithm = parse_pcr_bank(bank)?;
    let slots = parse_slots(slots)?;
    let selections = PcrSelectionList::builder()
        .with_selection(hash_algorithm, slots.as_slice())
        .build()?;
    Ok(selections)
}

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
    fn parse_no_bank_delimiter() {
        let parsed = parse_pcr_selection_list("1,2,3");
        assert_eq!(
            parsed,
            Err(PcrError::InvalidPcrSelectionString("1,2,3".to_string()))
        );
    }

    #[test]
    fn parse_no_bank() {
        let parsed = parse_pcr_selection_list(":1,2,3");
        assert_eq!(parsed, Err(PcrError::InvalidPcrBank("".to_string())));
    }

    #[test]
    fn parse_bad_bank() {
        let parsed = parse_pcr_selection_list("bunk:1,2,3");
        assert_eq!(parsed, Err(PcrError::InvalidPcrBank("bunk".to_string())));
    }

    #[test]
    fn parse_no_selections() {
        let parsed = parse_pcr_selection_list("sha1:");
        assert!(parsed.is_err());
    }

    #[test]
    fn parse_bad_slot() {
        let parsed = parse_pcr_selection_list("sha1:1,bad,2");
        assert_eq!(parsed, Err(PcrError::InvalidPcrSlot("bad".to_string())));
    }

    #[test]
    fn parse_out_of_range_slot() {
        let parsed = parse_pcr_selection_list("sha1:1,32");
        assert_eq!(parsed, Err(PcrError::InvalidPcrSlot("32".to_string())));
    }

    #[test]
    fn parse_happy_sha1() -> Result<()> {
        let expected = PcrSelectionList::builder()
            .with_selection(HashingAlgorithm::Sha1, &[PcrSlot::Slot1])
            .build()?;
        let parsed = parse_pcr_selection_list("sha1:1")?;
        assert_eq!(expected, parsed);
        let expected = PcrSelectionList::builder()
            .with_selection(
                HashingAlgorithm::Sha1,
                &[PcrSlot::Slot0, PcrSlot::Slot1, PcrSlot::Slot9],
            )
            .build()?;
        let parsed = parse_pcr_selection_list("sha1:0,1,9")?;
        assert_eq!(expected, parsed);
        Ok(())
    }
}
