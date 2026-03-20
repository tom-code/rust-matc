use anyhow::{Context, Ok, Result};

use crate::device_messages::AttrReport;
use crate::{clusters, device_messages, messages, tlv};

use super::Device;
use super::types::{ActiveSubscription, PendingChunkState, SubscribeState, SubscribedPaths};


const COMPUTED_ATTRS: &[(u16, u32, u32)] = &[
    (
        0,
        clusters::defs::CLUSTER_ID_OPERATIONAL_CREDENTIALS,
        clusters::defs::CLUSTER_OPERATIONAL_CREDENTIALS_ATTR_ID_CURRENTFABRICINDEX,
    ),
    (
        0,
        clusters::defs::CLUSTER_ID_OPERATIONAL_CREDENTIALS,
        clusters::defs::CLUSTER_OPERATIONAL_CREDENTIALS_ATTR_ID_NOCS,
    ),
    (
        0,
        clusters::defs::CLUSTER_ID_OPERATIONAL_CREDENTIALS,
        clusters::defs::CLUSTER_OPERATIONAL_CREDENTIALS_ATTR_ID_TRUSTEDROOTCERTIFICATES,
    ),
];

/// Estimated encoded byte size of one AttrReport inside a ReportData body.
fn estimate_report_bytes(report: &AttrReport) -> usize {
    // Path wrapper overhead: ~30 bytes (anon struct + AttributeDataIB struct +
    // DataVersion uint32 + AttributePathIB list + endpoint uint16 + cluster uint32
    // + attribute uint32 + closing tags).
    const PATH_OVERHEAD: usize = 30;
    match report {
        AttrReport::Data { value_tlv, .. } => PATH_OVERHEAD + value_tlv.len(),
        AttrReport::Status { .. } => 20,
    }
}


fn take_chunk(reports: &mut Vec<AttrReport>) -> Vec<AttrReport> {
    const MAX_CHUNK_BYTES: usize = 800;
    let mut size = 0usize;
    let mut count = 0usize;
    for report in reports.iter() {
        let est = estimate_report_bytes(report);
        if count > 0 && size + est > MAX_CHUNK_BYTES {
            break;
        }
        size += est;
        count += 1;
    }
    reports.drain(..count).collect()
}

impl Device {
    /// Find the fabric_index for a CASE session by session_id.
    /// Returns 0 if not found (PASE or unknown).
    fn session_fabric_index(&self, session_id: u16) -> u8 {
        self.case_sessions
            .iter()
            .find(|s| s.my_session_id == session_id)
            .map(|s| s.fabric_index)
            .unwrap_or(0)
    }

    fn compute_attribute(&self, ep: u16, cluster: u32, attr: u32, fabric_index: u8) -> Option<Vec<u8>> {
        use clusters::defs::*;
        match (ep, cluster, attr) {
            (0, CLUSTER_ID_OPERATIONAL_CREDENTIALS, CLUSTER_OPERATIONAL_CREDENTIALS_ATTR_ID_CURRENTFABRICINDEX) => {
                let mut buf = tlv::TlvBuffer::new();
                let _ = buf.write_uint8(2, fabric_index);
                Some(buf.data)
            }
            (0, CLUSTER_ID_OPERATIONAL_CREDENTIALS, CLUSTER_OPERATIONAL_CREDENTIALS_ATTR_ID_NOCS) => {
                let mut buf = tlv::TlvBuffer::new();
                let _ = buf.write_array(2);
                for fi in &self.fabrics {
                    if fi.fabric_index == fabric_index {
                        let _ = buf.write_anon_struct();
                        let _ = buf.write_octetstring(1, &fi.noc);
                        if let Some(icac) = &fi.icac {
                            let _ = buf.write_octetstring(2, icac);
                        }
                        let _ = buf.write_uint8(254, fi.fabric_index); // FabricIndex tag
                        let _ = buf.write_struct_end();
                    }
                }
                let _ = buf.write_struct_end();
                Some(buf.data)
            }
            (0, CLUSTER_ID_OPERATIONAL_CREDENTIALS, CLUSTER_OPERATIONAL_CREDENTIALS_ATTR_ID_TRUSTEDROOTCERTIFICATES) => {
                let mut buf = tlv::TlvBuffer::new();
                let _ = buf.write_array(2);
                for fi in &self.fabrics {
                    if fi.fabric_index == fabric_index {
                        let _ = buf.write_octetstring_notag(&fi.trusted_root_cert);
                    }
                }
                let _ = buf.write_struct_end();
                Some(buf.data)
            }
            _ => None,
        }
    }

    fn resolve_attribute_paths(&self, entries: &[tlv::TlvItem], session_id: u16) -> Vec<AttrReport> {
        let fabric_index = self.session_fabric_index(session_id);
        let mut reports = Vec::new();
        for path in entries {
            let endpoint = path.get_int(&[2]).map(|v| v as u16);
            let cluster = path.get_int(&[3]).map(|v| v as u32);
            let attribute = path.get_int(&[4]).map(|v| v as u32);

            let is_wildcard = endpoint.is_none() || cluster.is_none() || attribute.is_none();

            if is_wildcard {
                // Wildcard: iterate computed attributes first.
                for &(ep, cl, at) in COMPUTED_ATTRS {
                    if endpoint.is_none_or(|e| e == ep)
                        && cluster.is_none_or(|c| c == cl)
                        && attribute.is_none_or(|a| a == at)
                    {
                        if let Some(value_tlv) = self.compute_attribute(ep, cl, at, fabric_index) {
                            reports.push(AttrReport::Data {
                                endpoint: ep,
                                cluster: cl,
                                attribute: at,
                                value_tlv,
                            });
                        }
                    }
                }
                // Then iterate all stored attributes.
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
                // Try computed first, then fall back to HashMap.
                if let Some(value_tlv) = self.compute_attribute(ep, cl, at, fabric_index) {
                    reports.push(AttrReport::Data {
                        endpoint: ep,
                        cluster: cl,
                        attribute: at,
                        value_tlv,
                    });
                } else if let Some(value_tlv) = self.attributes.get(&(ep, cl, at)) {
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
        handler: &mut dyn super::AppHandler,
    ) -> Result<()> {
        let invoke_tlv = tlv::decode_tlv(proto_payload)?;
        let endpoint = invoke_tlv.get_int(&[2, 0, 0, 0]).unwrap_or(1) as u16;
        let cluster = invoke_tlv
            .get_int(&[2, 0, 0, 1])
            .context("invoke: cluster missing")? as u32;
        let command = invoke_tlv
            .get_int(&[2, 0, 0, 2])
            .context("invoke: command missing")? as u32;
        log::info!(
            "IM: InvokeRequest endpoint={} cluster=0x{:04x} command=0x{:02x}",
            endpoint,
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
                CLUSTER_OPERATIONAL_CREDENTIALS_CMD_ID_UPDATEFABRICLABEL,
            ) => {
                self.handle_update_fabric_label(addr, msg_header, proto_header, &invoke_tlv)
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
                let mut ctx = super::AttrContext {
                    attributes: &mut self.attributes,
                    dirty: &mut self.dirty_attributes,
                };
                let result = handler.handle_command(
                    endpoint,
                    cluster,
                    command,
                    &invoke_tlv,
                    &mut ctx,
                );
                let status_code = match result {
                    super::CommandResult::Success => 0u16,
                    super::CommandResult::Error(code) => code,
                    super::CommandResult::Unhandled => {
                        log::warn!(
                            "Unhandled invoke: cluster=0x{:04x} command=0x{:02x}",
                            cluster,
                            command
                        );
                        0x81 // UNSUPPORTED_COMMAND
                    }
                };
                let resp = device_messages::im_invoke_response_status(
                    proto_header.exchange_id,
                    endpoint,
                    cluster,
                    command,
                    status_code,
                    msg_header.message_counter as i64,
                )?;
                self.send_reply_by_session(addr, msg_header.session_id, &resp)
                    .await
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
                self.resolve_attribute_paths(entries, msg_header.session_id)
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        log::debug!("Read request: {} attribute path(s)", reports.len());

        let mut remaining = reports;
        let first_chunk = take_chunk(&mut remaining);
        let more = !remaining.is_empty();
        if more {
            self.pending_chunks.push(PendingChunkState {
                exchange_id: proto_header.exchange_id,
                remaining,
                subscription_id: None,
            });
        }
        let resp = device_messages::im_report_data(
            proto_header.exchange_id,
            &first_chunk,
            msg_header.message_counter as i64,
            None,
            more,
        )?;
        log::debug!("Read response: chunk size={} more={}", resp.len(), more);
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
        // Tag 0: KeepSubscriptions (bool), Tag 1: MinIntervalFloor (u16), Tag 2: MaxIntervalCeiling (u16)
        let max_interval_secs = sub_tlv.get_int(&[2]).map(|v| v as u16).unwrap_or(120);

        let mut is_wildcard = true;
        let reports: Vec<AttrReport> = if let Some(attr_req) = sub_tlv.get_item(&[3]) {
            if let tlv::TlvItemValue::List(entries) = &attr_req.value {
                log::debug!(
                    "Subscribe: {} specific attribute path(s) requested",
                    entries.len()
                );
                is_wildcard = false;
                self.resolve_attribute_paths(entries, msg_header.session_id)
            } else {
                vec![]
            }
        } else {
            log::debug!("Subscribe: no AttributeRequests — sending all attributes (wildcard)");
            let fabric_index = self.session_fabric_index(msg_header.session_id);
            let mut all: Vec<AttrReport> = COMPUTED_ATTRS
                .iter()
                .filter_map(|&(ep, cl, at)| {
                    self.compute_attribute(ep, cl, at, fabric_index).map(|value_tlv| AttrReport::Data {
                        endpoint: ep,
                        cluster: cl,
                        attribute: at,
                        value_tlv,
                    })
                })
                .collect();
            all.extend(self.attributes.iter().map(
                |(&(endpoint, cluster, attribute), value_tlv)| AttrReport::Data {
                    endpoint,
                    cluster,
                    attribute,
                    value_tlv: value_tlv.clone(),
                },
            ));
            all
        };

        let paths = if is_wildcard {
            SubscribedPaths::All
        } else {
            SubscribedPaths::Specific(
                reports
                    .iter()
                    .filter_map(|r| match r {
                        AttrReport::Data { endpoint, cluster, attribute, .. } => {
                            Some((*endpoint, *cluster, *attribute))
                        }
                        _ => None,
                    })
                    .collect(),
            )
        };

        let subscription_id = rand::random::<u32>();
        self.subscribe_states.push(SubscribeState {
            exchange_id: proto_header.exchange_id,
            subscription_id,
            paths,
            max_interval_secs,
        });

        let mut remaining = reports;
        let first_chunk = take_chunk(&mut remaining);
        let more = !remaining.is_empty();
        if more {
            log::info!(
                "Subscribe: chunking response — {} reports remain after first chunk",
                remaining.len()
            );
            self.pending_chunks.push(PendingChunkState {
                exchange_id: proto_header.exchange_id,
                remaining,
                subscription_id: Some(subscription_id),
            });
        }
        let resp = device_messages::im_report_data(
            proto_header.exchange_id,
            &first_chunk,
            msg_header.message_counter as i64,
            Some(subscription_id),
            more,
        )?;
        log::info!(
            "Subscribe: sending first chunk size={} more={} sub_id={} exchange={}",
            resp.len(),
            more,
            subscription_id,
            proto_header.exchange_id,
        );
        self.send_reply_by_session(addr, msg_header.session_id, &resp)
            .await
    }

    pub(crate) async fn handle_write_request(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        proto_payload: &[u8],
    ) -> Result<()> {
        // Parse attribute paths from WriteRequest; echo each back with SUCCESS status.
        // tag 2 = WriteRequests array; within each AttributeDataIB: tag 1 = AttributePathIB,
        // then tag 2 = Endpoint, tag 3 = Cluster, tag 4 = Attribute.
        let mut paths: Vec<(u16, u32, u32)> = Vec::new();
        if let Some(write_tlv) = tlv::decode_tlv(proto_payload).ok() {
            if let Some(writes_item) = write_tlv.get_item(&[2]) {
                if let tlv::TlvItemValue::List(entries) = &writes_item.value {
                    for entry in entries {
                        let endpoint = entry.get_int(&[1, 2]).unwrap_or(0) as u16;
                        let cluster = entry.get_int(&[1, 3]).unwrap_or(0) as u32;
                        let attribute = entry.get_int(&[1, 4]).unwrap_or(0) as u32;
                        log::info!(
                            "Write: endpoint={} cluster={:#06x} attribute={:#06x}",
                            endpoint, cluster, attribute
                        );
                        if let Some(data_item) = entry.get_item(&[2]) {
                            if let Some(raw) = tlv_item_to_raw(data_item) {
                                self.set_attribute_raw(endpoint, cluster, attribute, &raw);
                            }
                        }
                        paths.push((endpoint, cluster, attribute));
                    }
                }
            }
        }
        let resp = device_messages::im_write_response_success(
            proto_header.exchange_id,
            msg_header.message_counter as i64,
            &paths,
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

        // If there are pending report chunks for this exchange, send the next one.
        // Only proceed to SubscribeResponse logic after all chunks are delivered.
        let chunk_idx = self
            .pending_chunks
            .iter()
            .position(|c| c.exchange_id == proto_header.exchange_id);
        if let Some(idx) = chunk_idx {
            let sub_id = self.pending_chunks[idx].subscription_id;
            let chunk = take_chunk(&mut self.pending_chunks[idx].remaining);
            let more = !self.pending_chunks[idx].remaining.is_empty();
            if !more {
                self.pending_chunks.remove(idx);
            }
            let resp = device_messages::im_report_data(
                proto_header.exchange_id,
                &chunk,
                msg_header.message_counter as i64,
                sub_id,
                more,
            )?;
            log::debug!(
                "Sending next chunk: size={} more={} exchange={}",
                resp.len(),
                more,
                proto_header.exchange_id,
            );
            let _ = self
                .send_reply_by_session(addr, msg_header.session_id, &resp)
                .await;
            return Ok(());
        }

        // Only send Subscribe Response if this Status Response belongs to an active subscription exchange
        let matching_idx = self
            .subscribe_states
            .iter()
            .position(|s| s.exchange_id == proto_header.exchange_id);
        if let Some(idx) = matching_idx {
            let state = self.subscribe_states.remove(idx);
            let subscription_id = state.subscription_id;
            let max_interval_secs = state.max_interval_secs;
            let paths = state.paths;
            let sub_resp = device_messages::im_subscribe_response(
                subscription_id,
                proto_header.exchange_id,
                msg_header.message_counter as i64,
                max_interval_secs,
            )?;
            let _ = self
                .send_reply_by_session(addr, msg_header.session_id, &sub_resp)
                .await;
            self.active_subscriptions.push(ActiveSubscription {
                subscription_id,
                session_id: msg_header.session_id,
                peer_addr: *addr,
                max_interval_secs,
                paths,
            });
        }
        Ok(())
    }

    pub(crate) async fn send_subscription_report(&mut self) -> Result<()> {
        if self.active_subscriptions.is_empty() {
            return Ok(());
        }

        // Clone subscription metadata to avoid holding a borrow on self.active_subscriptions
        // while also accessing self.dirty_attributes, self.attributes, and calling methods.
        let subs: Vec<(u32, u16, std::net::SocketAddr, SubscribedPaths)> = self
            .active_subscriptions
            .iter()
            .map(|s| (s.subscription_id, s.session_id, s.peer_addr, s.paths.clone()))
            .collect();

        for (sub_id, session_id, peer_addr, paths) in &subs {
            let changed_reports: Vec<AttrReport> = self
                .dirty_attributes
                .iter()
                .filter(|&&(ep, cl, at)| match paths {
                    SubscribedPaths::All => true,
                    SubscribedPaths::Specific(keys) => keys.contains(&(ep, cl, at)),
                })
                .filter_map(|&(ep, cl, at)| {
                    self.attributes.get(&(ep, cl, at)).map(|tlv| AttrReport::Data {
                        endpoint: ep,
                        cluster: cl,
                        attribute: at,
                        value_tlv: tlv.clone(),
                    })
                })
                .collect();

            let exchange_id: u16 = rand::random();
            let data = device_messages::im_report_data_unsolicited(
                exchange_id,
                &changed_reports,
                *sub_id,
            )?;
            log::info!(
                "Sending subscription report (sub_id={}, {} changed attrs)",
                sub_id,
                changed_reports.len()
            );
            if let Err(e) = self
                .send_reply_by_session(peer_addr, *session_id, &data)
                .await
            {
                log::warn!(
                    "Failed to send report for sub_id={}: {:?}",
                    sub_id,
                    e
                );
            }
        }

        self.dirty_attributes.clear();
        Ok(())
    }
}

/// Re-encode a decoded TlvItem back to raw TLV bytes (using the item's original tag).
/// Used to store written attribute values back into the attribute map.
fn tlv_item_to_raw(item: &tlv::TlvItem) -> Option<Vec<u8>> {
    let mut buf = tlv::TlvBuffer::new();
    match &item.value {
        tlv::TlvItemValue::String(s) => buf.write_string(item.tag, s).ok()?,
        tlv::TlvItemValue::Int(i) => {
            if *i <= u8::MAX as u64 {
                buf.write_uint8(item.tag, *i as u8).ok()?;
            } else if *i <= u16::MAX as u64 {
                buf.write_uint16(item.tag, *i as u16).ok()?;
            } else if *i <= u32::MAX as u64 {
                buf.write_uint32(item.tag, *i as u32).ok()?;
            } else {
                buf.write_uint64(item.tag, *i).ok()?;
            }
        }
        tlv::TlvItemValue::Bool(b) => buf.write_bool(item.tag, *b).ok()?,
        tlv::TlvItemValue::OctetString(bytes) => buf.write_octetstring(item.tag, bytes).ok()?,
        _ => return None,
    }
    Some(buf.data)
}
