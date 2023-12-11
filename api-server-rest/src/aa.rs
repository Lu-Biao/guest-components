// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::router::ApiHandler;
use crate::ttrpc_proto::attestation_agent::ExtendRuntimeMeasurementRequest;
use crate::ttrpc_proto::attestation_agent::{GetEvidenceRequest, GetTokenRequest};
use crate::ttrpc_proto::attestation_agent_ttrpc::AttestationAgentServiceClient;
use anyhow::*;
use async_trait::async_trait;
use hyper::{Body, Method, Request, Response};
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::TTRPC_TIMEOUT;

/// ROOT path for Confidential Data Hub API
pub const AA_ROOT: &str = "/aa";

/// URL for querying CDH get resource API
const AA_TOKEN_URL: &str = "/token";
const AA_EVIDENCE_URL: &str = "/evidence";
const AA_MEASUREMENT_URL: &str = "/measurement";

pub struct AAClient {
    client: AttestationAgentServiceClient,
    accepted_method: Vec<Method>,
}

#[async_trait]
impl ApiHandler for AAClient {
    async fn handle_request(
        &self,
        remote_addr: SocketAddr,
        url_path: &str,
        req: Request<Body>,
    ) -> Result<Response<Body>> {
        if !remote_addr.ip().is_loopback() {
            // Return 403 Forbidden response.
            return self.forbidden();
        }

        if !self.accepted_method.iter().any(|i| i.eq(&req.method())) {
            // Return 405 Method Not Allowed response.
            return self.not_allowed();
        }

        let params: HashMap<String, String> = req
            .uri()
            .query()
            .map(|v| form_urlencoded::parse(v.as_bytes()).into_owned().collect())
            .unwrap_or_default();

        if params.len() != 1 {
            return self.not_allowed();
        }

        match url_path {
            AA_TOKEN_URL => match params.get("token_type") {
                Some(token_type) => {
                    let results = self
                        .get_token(token_type)
                        .await
                        .unwrap_or_else(|e| e.to_string().into());
                    return self.octet_stream_response(results);
                }
                None => return self.bad_request(),
            },
            AA_EVIDENCE_URL => match params.get("runtime_data") {
                Some(runtime_data) => {
                    let results = self
                        .get_evidence(&runtime_data.clone().into_bytes())
                        .await
                        .unwrap_or_else(|e| e.to_string().into());
                    return self.octet_stream_response(results);
                }
                None => return self.bad_request(),
            },
            AA_MEASUREMENT_URL => match params.get("event") {
                Some(event) => {
                    let results = self
                        .extend_runtime_measurement(&event.clone().into_bytes())
                        .await
                        .unwrap_or_else(|e| e.to_string().into());
                    return self.octet_stream_response(results);
                }
                None => return self.bad_request(),
            },

            _ => {
                return self.not_found();
            }
        }
    }
}

impl AAClient {
    pub fn new(aa_addr: &str, accepted_method: Vec<Method>) -> Result<Self> {
        let inner = ttrpc::asynchronous::Client::connect(aa_addr)
            .context(format!("ttrpc connect to AA addr: {} failed!", aa_addr))?;
        let client = AttestationAgentServiceClient::new(inner);

        Ok(Self {
            client,
            accepted_method,
        })
    }

    pub async fn get_token(&self, token_type: &str) -> Result<Vec<u8>> {
        let req = GetTokenRequest {
            TokenType: token_type.to_string(),
            ..Default::default()
        };
        let res = self
            .client
            .get_token(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        Ok(res.Token)
    }

    pub async fn get_evidence(&self, runtime_data: &[u8]) -> Result<Vec<u8>> {
        let req = GetEvidenceRequest {
            RuntimeData: runtime_data.to_vec(),
            ..Default::default()
        };
        let res = self
            .client
            .get_evidence(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        Ok(res.Evidence)
    }

    pub async fn extend_runtime_measurement(&self, event: &[u8]) -> Result<Vec<u8>> {
        let req = ExtendRuntimeMeasurementRequest {
            Events: vec![event.to_vec()],
            ..Default::default()
        };
        let _ = self
            .client
            .extend_runtime_measurement(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;

        Ok(vec![])
    }
}
