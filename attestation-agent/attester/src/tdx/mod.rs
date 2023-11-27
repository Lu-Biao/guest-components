// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::*;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use std::mem;
use std::path::Path;
use tdx_attest_rs;

const CCEL_PATH: &str = "/sys/firmware/acpi/tables/data/CCEL";

pub fn detect_platform() -> bool {
    Path::new("/dev/tdx-attest").exists() || Path::new("/dev/tdx-guest").exists()
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

#[async_trait::async_trait]
impl Attester for TdxAttester {
    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<String> {
        if report_data.len() > 64 {
            bail!("TDX Attester: Report data must be no more than 64 bytes");
        }

        report_data.resize(64, 0);

        let tdx_report_data = tdx_attest_rs::tdx_report_data_t {
            d: report_data.as_slice().try_into()?,
        };

        let engine = base64::engine::general_purpose::STANDARD;
        let quote = match tdx_attest_rs::tdx_att_get_quote(Some(&tdx_report_data), None, None, 0) {
            (tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS, Some(q)) => engine.encode(q),
            (error_code, _) => {
                return Err(anyhow!(
                    "TDX Attester: Failed to get TD quote. Error code: {:?}",
                    error_code
                ));
            }
        };

        let cc_eventlog = match std::fs::read(CCEL_PATH) {
            Result::Ok(el) => Some(engine.encode(el)),
            Result::Err(e) => {
                log::warn!("Read CC Eventlog failed: {:?}", e);
                None
            }
        };

        let evidence = TdxEvidence { cc_eventlog, quote };

        serde_json::to_string(&evidence)
            .map_err(|e| anyhow!("Serialize TDX evidence failed: {:?}", e))
    }

    async fn extend_runtime_measurement(
        &self,
        events: Vec<Vec<u8>>,
        _register_index: Option<u64>,
    ) -> Result<()> {
        for event in events {
            unsafe {
                let mut event_buffer = [0u8; mem::size_of::<tdx_attest_rs::tdx_rtmr_event_t>()];
                let rtmr_event =
                    &mut *(event_buffer.as_mut_ptr() as *mut tdx_attest_rs::tdx_rtmr_event_t);
                rtmr_event.version = 1;
                rtmr_event.rtmr_index = 2;
                let mut hasher = Sha384::new();
                hasher.update(&event);
                let hash = hasher.finalize().to_vec();
                rtmr_event.extend_data.copy_from_slice(&hash);

                log::info!(
                    "test tdx_att_extend event: {:?}",
                    String::from_utf8(event).expect("Our bytes should be valid utf8")
                );
                log::info!("test tdx_att_extend event_buffer: {:?}", event_buffer);
                log::info!("test tdx_att_extend hash: {:?}", hash);

                match tdx_attest_rs::tdx_att_extend(&event_buffer) {
                    tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS => {
                        log::debug!("TDX extend runtime measurement succeeded.")
                    }
                    error_code => {
                        bail!(
                            "TDX Attester: Failed to extend RTMR. Error code: {:?}",
                            error_code
                        );
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[tokio::test]
    async fn test_tdx_get_evidence() {
        let attester = TdxAttester::default();
        let report_data: Vec<u8> = vec![0; 48];

        let evidence = attester.get_evidence(report_data).await;
        assert!(evidence.is_ok());
    }
}
