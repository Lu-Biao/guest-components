// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::*;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io;

const CCEL_PATH: &str = "/sys/firmware/acpi/tables/data/CCEL";

pub fn detect_platform() -> bool {
    log::info!("tdx detect_platform return true by force.");
    true
}

#[derive(Serialize, Deserialize)]
struct TdxEvidence {
    // Base64 encoded CC Eventlog ACPI table
    // refer to https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#cc-event-log-acpi-table.
    cc_eventlog: Option<String>,
    // Base64 encoded TD quote.
    quote: String,
}

#[derive(Debug, Default)]
pub struct TdxAttester {}

impl Attester for TdxAttester {
    fn get_evidence(&self, _report_data: String) -> Result<String> {

        let cc_eventlog = match std::fs::read(CCEL_PATH) {
            Result::Ok(el) => Some(base64::encode(el)),
            Result::Err(e) => {
                log::warn!("Read CC Eventlog failed: {:?}", e);
                None
            }
        };

        let f = File::open("quote_base64.dat")?;
        let q = io::read_to_string(f)?;
        let evidence = TdxEvidence { cc_eventlog: cc_eventlog, quote: q };

        serde_json::to_string(&evidence)
            .map_err(|e| anyhow!("Serialize TDX evidence failed: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[test]
    fn test_tdx_get_evidence() {
        let attester = TdxAttester::default();
        let report_data: Vec<u8> = vec![0; 48];
        let report_data_base64 = base64::encode(report_data);

        let evidence = attester.get_evidence(report_data_base64);
        assert!(evidence.is_ok());
    }
}
