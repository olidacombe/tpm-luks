///
/// # Get Started
///
/// ```bash
/// # at basecamp
/// fswatch -o . | xargs -n1 -I{} ./sync.sh
/// # on remote (e.g. Metal) machine
/// TCTI=device:/dev/tpm0 cargo watch -x test
/// ```

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    #[test]
    fn bla() {
        use tss_esapi::{
            interface_types::algorithm::HashingAlgorithm,
            structures::{PcrSelectionListBuilder, PcrSlot},
            tcti_ldr::TctiNameConf,
            Context,
        };
        let mut context =
            Context::new(TctiNameConf::from_environment_variable().expect("Failed to get TCTI"))
                .expect("Failed to create Context");
        // Create PCR selection list with slots in a bank
        // that is going to be read.
        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(
                HashingAlgorithm::Sha256,
                &[
                    PcrSlot::Slot0,
                    PcrSlot::Slot1,
                    PcrSlot::Slot2,
                    PcrSlot::Slot3,
                    PcrSlot::Slot4,
                    PcrSlot::Slot5,
                    PcrSlot::Slot6,
                    PcrSlot::Slot7,
                    PcrSlot::Slot8,
                    PcrSlot::Slot9,
                    PcrSlot::Slot10,
                    PcrSlot::Slot11,
                    PcrSlot::Slot12,
                    PcrSlot::Slot13,
                    PcrSlot::Slot14,
                    PcrSlot::Slot15,
                    PcrSlot::Slot16,
                    PcrSlot::Slot17,
                    PcrSlot::Slot18,
                    PcrSlot::Slot19,
                    PcrSlot::Slot20,
                    PcrSlot::Slot21,
                ],
            )
            .build()
            .expect("Failed to build PcrSelectionList");
        //let _pcr_data = tss_esapi::abstraction::pcr::read_all(&mut context, pcr_selection_list)
        //.expect("pcr::read_all failed");
    }
}
