use anyhow::{Context, Ok, Result};

use crate::device_messages::AttrReport;
use crate::{clusters, device_messages, messages, tlv};

use super::Device;
use super::types::{ActiveSubscription, SubscribeState};

impl Device {
    fn resolve_attribute_paths(&self, entries: &[tlv::TlvItem]) -> Vec<AttrReport> {
        let mut reports = Vec::new();
        for path in entries {
            let endpoint = path.get_int(&[2]).map(|v| v as u16);
            let cluster = path.get_int(&[3]).map(|v| v as u32);
            let attribute = path.get_int(&[4]).map(|v| v as u32);

            let is_wildcard = endpoint.is_none() || cluster.is_none() || attribute.is_none();

            if is_wildcard {
                // Wildcard: iterate all stored attributes and filter by whichever fields are present.
                for (&(ep, cl, at), value_tlv) in &self.attributes {
                    if endpoint.is_none_or(|e| e == ep)
                        && cluster.is_none_or(|c| c == cl)
                        && attribute.is_none_or(|a| a == at)
                    {
                        reports.push(AttrReport::Data {
                            endpoint: ep,
                            cluster: cl,
                            attribute: at,
                            value_tlv: value_tlv.clone(),
                        });
                    }
                }
            } else {
                // Exact lookup — all three fields are present.
                let (ep, cl, at) = (endpoint.unwrap(), cluster.unwrap(), attribute.unwrap());
                if let Some(value_tlv) = self.attributes.get(&(ep, cl, at)) {
                    reports.push(AttrReport::Data {
                        endpoint: ep,
                        cluster: cl,
                        attribute: at,
                        value_tlv: value_tlv.clone(),
                    });
                } else {
                    log::warn!(
                        "Attribute not found: endpoint={} cluster=0x{:04x}/{:?} attribute=0x{:04x}",
                        ep,
                        cl,
                        clusters::names::get_cluster_name(cl),
                        at
                    );
                    reports.push(AttrReport::Status {
                        endpoint: ep,
                        cluster: cl,
                        attribute: at,
                        status: messages::ProtocolMessageHeader::IM_STATUS_UNSUPPORTED_ATTRIBUTE,
                    });
                }
            }
        }
        reports
    }

    pub(crate) async fn handle_invoke_request(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        proto_payload: &[u8],
    ) -> Result<()> {
        let invoke_tlv = tlv::decode_tlv(proto_payload)?;
        let cluster = invoke_tlv
            .get_int(&[2, 0, 0, 1])
            .context("invoke: cluster missing")? as u32;
        let command = invoke_tlv
            .get_int(&[2, 0, 0, 2])
            .context("invoke: command missing")? as u32;
        log::info!(
            "IM: InvokeRequest cluster=0x{:04x} command=0x{:02x}",
            cluster,
            command
        );

        use clusters::defs::*;
        match (cluster, command) {
            (
                CLUSTER_ID_GENERAL_COMMISSIONING,
                CLUSTER_GENERAL_COMMISSIONING_CMD_ID_ARMFAILSAFE,
            ) => {
                self.handle_arm_failsafe(addr, msg_header, proto_header, &invoke_tlv)
                    .await
            }
            (
                CLUSTER_ID_GENERAL_COMMISSIONING,
                CLUSTER_GENERAL_COMMISSIONING_CMD_ID_SETREGULATORYCONFIG,
            ) => {
                self.handle_set_regulatory_config(addr, msg_header, proto_header)
                    .await
            }
            (
                CLUSTER_ID_OPERATIONAL_CREDENTIALS,
                CLUSTER_OPERATIONAL_CREDENTIALS_CMD_ID_ATTESTATIONREQUEST,
            ) => {
                self.handle_attestation_request(addr, msg_header, proto_header, &invoke_tlv)
                    .await
            }
            (
                CLUSTER_ID_OPERATIONAL_CREDENTIALS,
                CLUSTER_OPERATIONAL_CREDENTIALS_CMD_ID_CERTIFICATECHAINREQUEST,
            ) => {
                self.handle_cert_chain_request(addr, msg_header, proto_header, &invoke_tlv)
                    .await
            }
            (
                CLUSTER_ID_OPERATIONAL_CREDENTIALS,
                CLUSTER_OPERATIONAL_CREDENTIALS_CMD_ID_CSRREQUEST,
            ) => {
                self.handle_csr_request(addr, msg_header, proto_header, &invoke_tlv)
                    .await
            }
            (
                CLUSTER_ID_OPERATIONAL_CREDENTIALS,
                CLUSTER_OPERATIONAL_CREDENTIALS_CMD_ID_ADDTRUSTEDROOTCERTIFICATE,
            ) => {
                self.handle_add_trusted_root(addr, msg_header, proto_header, &invoke_tlv)
                    .await
            }
            (CLUSTER_ID_OPERATIONAL_CREDENTIALS, CLUSTER_OPERATIONAL_CREDENTIALS_CMD_ID_ADDNOC) => {
                self.handle_add_noc(addr, msg_header, proto_header, &invoke_tlv)
                    .await
            }
            (
                CLUSTER_ID_OPERATIONAL_CREDENTIALS,
                CLUSTER_OPERATIONAL_CREDENTIALS_CMD_ID_REMOVEFABRIC,
            ) => {
                self.handle_remove_fabric(addr, msg_header, proto_header, &invoke_tlv)
                    .await
            }
            (
                CLUSTER_ID_GENERAL_COMMISSIONING,
                CLUSTER_GENERAL_COMMISSIONING_CMD_ID_COMMISSIONINGCOMPLETE,
            ) => {
                self.handle_commissioning_complete(addr, msg_header, proto_header)
                    .await
            }
            _ => {
                log::warn!(
                    "Unhandled invoke: cluster=0x{:04x} command=0x{:02x}",
                    cluster,
                    command
                );
                Ok(())
            }
        }
    }

    pub(crate) async fn handle_read_request(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        proto_payload: &[u8],
    ) -> Result<()> {
        let read_tlv = tlv::decode_tlv(proto_payload)?;
        let reports: Vec<AttrReport> = if let Some(arr_item) = read_tlv.get_item(&[0]) {
            if let tlv::TlvItemValue::List(entries) = &arr_item.value {
                self.resolve_attribute_paths(entries)
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        log::debug!("Read request: {} attribute path(s)", reports.len());

        let resp = device_messages::im_report_data(
            proto_header.exchange_id,
            &reports,
            msg_header.message_counter as i64,
            None,
        )?;

        self.send_reply_by_session(addr, msg_header.session_id, &resp)
            .await
    }

    pub(crate) async fn handle_subscribe_request(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        proto_payload: &[u8],
    ) -> Result<()> {
        log::info!("Subscribe request");
        let sub_tlv = tlv::decode_tlv(proto_payload)?;
        sub_tlv.dump(1);

        let reports: Vec<AttrReport> = if let Some(attr_req) = sub_tlv.get_item(&[3]) {
            if let tlv::TlvItemValue::List(entries) = &attr_req.value {
                log::debug!(
                    "Subscribe: {} specific attribute path(s) requested",
                    entries.len()
                );
                self.resolve_attribute_paths(entries)
            } else {
                vec![]
            }
        } else {
            log::debug!("Subscribe: no AttributeRequests — sending all attributes (wildcard)");
            self.attributes
                .iter()
                .map(
                    |(&(endpoint, cluster, attribute), value_tlv)| AttrReport::Data {
                        endpoint,
                        cluster,
                        attribute,
                        value_tlv: value_tlv.clone(),
                    },
                )
                .collect()
        };

        let subscription_id = rand::random::<u32>();
        self.subscribe_states.push(SubscribeState {
            exchange_id: proto_header.exchange_id,
            subscription_id,
        });
        let resp = device_messages::im_report_data(
            proto_header.exchange_id,
            &reports,
            msg_header.message_counter as i64,
            Some(subscription_id),
        )?;
        self.send_reply_by_session(addr, msg_header.session_id, &resp)
            .await
    }

    pub(crate) async fn handle_write_request(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        _proto_payload: &[u8],
    ) -> Result<()> {
        log::warn!("Write request not supported, sending error response");
        let resp = device_messages::im_status_response(
            proto_header.exchange_id,
            messages::ProtocolMessageHeader::IM_STATUS_UNSUPPORTED_CLUSTER,
            msg_header.message_counter as i64,
        )?;
        self.send_reply_by_session(addr, msg_header.session_id, &resp)
            .await
    }

    pub(crate) async fn handle_status_response(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
    ) -> Result<()> {
        log::debug!("Received IM status response, sending ACK");
        // If the sender has no FLAG_INITIATOR, they are the responder — meaning we are
        // the initiator of this exchange (keepalive report). Our ACK must have FLAG_INITIATOR.
        let we_are_initiator =
            (proto_header.exchange_flags & messages::ProtocolMessageHeader::FLAG_INITIATOR) == 0;
        let ack_msg = if we_are_initiator {
            device_messages::device_ack_initiator(
                proto_header.exchange_id,
                msg_header.message_counter,
            )?
        } else {
            device_messages::device_ack(proto_header.exchange_id, msg_header.message_counter)?
        };
        let _ = self
            .send_reply_by_session(addr, msg_header.session_id, &ack_msg)
            .await;

        // Only send Subscribe Response if this Status Response belongs to an active subscription exchange
        let matching_idx = self
            .subscribe_states
            .iter()
            .position(|s| s.exchange_id == proto_header.exchange_id);
        if let Some(idx) = matching_idx {
            let subscription_id = self.subscribe_states[idx].subscription_id;
            self.subscribe_states.remove(idx);
            let sub_resp = device_messages::im_subscribe_response(
                subscription_id,
                proto_header.exchange_id,
                msg_header.message_counter as i64,
            )?;
            let _ = self
                .send_reply_by_session(addr, msg_header.session_id, &sub_resp)
                .await;
            self.active_subscriptions.push(ActiveSubscription {
                subscription_id,
                session_id: msg_header.session_id,
                peer_addr: *addr,
                max_interval_secs: 120,
            });
        }
        Ok(())
    }

    pub(crate) async fn send_subscription_report(&self) -> Result<()> {
        // triggered by timer. todo: send changes
        if self.active_subscriptions.is_empty() {
            return Ok(());
        }

        let reports: Vec<AttrReport> = vec![];

        for sub in &self.active_subscriptions {
            let exchange_id: u16 = rand::random();
            let data = device_messages::im_report_data_unsolicited(
                exchange_id,
                &reports,
                sub.subscription_id,
            )?;
            log::info!(
                "Sending subscription keepalive (sub_id={})",
                sub.subscription_id
            );
            if let Err(e) = self
                .send_reply_by_session(&sub.peer_addr, sub.session_id, &data)
                .await
            {
                log::warn!(
                    "Failed to send keepalive for sub_id={}: {:?}",
                    sub.subscription_id,
                    e
                );
            }
        }
        Ok(())
    }
}
