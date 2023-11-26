// Copyright (c) 2023 Intel
//
// SPDX-License-Identifier: Apache-2.0

use super::ttrpc_proto::attestation_agent::ExtendRuntimeMeasurementRequest;
use super::ttrpc_proto::attestation_agent_ttrpc::AttestationAgentServiceClient;
use super::Client;
use anyhow::*;
use async_trait::async_trait;
use ttrpc::context;

const SOCKET_ADDR: &str =
    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";

pub struct Ttrpc {
    aaclient: AttestationAgentServiceClient,
}

impl Ttrpc {
    pub fn new() -> Result<Self> {
        let inner = ttrpc::asynchronous::Client::connect(SOCKET_ADDR)?;
        let aaclient = AttestationAgentServiceClient::new(inner);
        Ok(Self { aaclient })
    }
}

#[async_trait]
impl Client for Ttrpc {
    async fn extend_runtime_measurement(&mut self, event: &str) -> Result<()> {
        let req = ExtendRuntimeMeasurementRequest {
            Events: vec![event.as_bytes().to_vec()],
            ..Default::default()
        };
        let _ = self
            .aaclient
            .extend_runtime_measurement(context::with_timeout(50 * 1000 * 1000 * 1000), &req)
            .await
            .map_err(|e| anyhow!("ttrpc error: {:?}", e))?;
        Ok(())
    }
}
