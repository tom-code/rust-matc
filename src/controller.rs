use std::{collections::HashMap, sync::Arc, time::Duration};

use crate::{
    active_connection::{ActiveConnection, Exchange},
    cert_matter, certmanager, commission, fabric, im,
    messages::{self, Message},
    retransmit, session, sigma, spake2p,
    tlv::TlvItemValue,
    transport::{self, ConnectionTrait},
    util::cryptoutil,
};
use anyhow::{Context, Result};
use tokio::sync::mpsc;
use byteorder::{LittleEndian, WriteBytesExt};

pub struct Controller {
    certmanager: Arc<dyn certmanager::CertManager>,
    #[allow(dead_code)]
    transport: Arc<transport::Transport>,
    fabric: fabric::Fabric,
    /// In-memory CASE session resumption records keyed by peer node ID.
    resumption: Arc<tokio::sync::Mutex<HashMap<u64, sigma::ResumptionRecord>>>,
}

pub struct Connection {
    active: ActiveConnection,
}
//trait IsSync: Sync {}
//impl IsSync for Controller {}

const CA_ID: u64 = 1;

#[derive(Debug, Clone, Copy)]
pub struct SigmaBusy {
    pub wait_ms: Option<u32>,
}
impl std::fmt::Display for SigmaBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.wait_ms {
            Some(ms) => write!(f, "responder BUSY (min wait {} ms)", ms),
            None => write!(f, "responder BUSY"),
        }
    }
}
impl std::error::Error for SigmaBusy {}

impl Controller {
    pub fn new(
        certmanager: &Arc<dyn certmanager::CertManager>,
        transport: &Arc<transport::Transport>,
        fabric_id: u64,
    ) -> Result<Arc<Self>> {
        let fabric = fabric::Fabric::new(
            fabric_id,
            CA_ID,
            &certmanager.get_ca_public_key()?,
            &certmanager.get_ipk_epoch_key(),
        );
        Ok(Arc::new(Self {
            certmanager: certmanager.clone(),
            transport: transport.clone(),
            fabric,
            resumption: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }))
    }

    /// commission device
    /// - authenticate using pin
    /// - push CA certificate to device
    /// - sign device's certificate
    /// - set controller id - user which can control device
    /// - return authenticated connection which can be used to send additional commands
    pub async fn commission(
        &self,
        connection: &Arc<dyn ConnectionTrait>,
        pin: u32,
        node_id: u64,
        controller_id: u64,
    ) -> Result<Connection> {
        let mut session = auth_spake(connection.as_ref(), pin).await?;
        let session = commission::commission(
            connection.as_ref(),
            &mut session,
            &self.fabric,
            self.certmanager.as_ref(),
            node_id,
            controller_id,
        )
        .await?;
        Ok(Connection {
            active: ActiveConnection::new(connection.clone(), session),
        })
    }

    /// create authenticated connection to control device
    pub async fn auth_sigma(
        &self,
        connection: &Arc<dyn ConnectionTrait>,
        node_id: u64,
        controller_id: u64,
    ) -> Result<Connection> {
        let (session, resumption) = auth_sigma(
            connection.as_ref(),
            &self.fabric,
            self.certmanager.as_ref(),
            node_id,
            controller_id,
        )
        .await?;
        if let Some(record) = resumption {
            self.resumption.lock().await.insert(node_id, record);
        }
        Ok(Connection {
            active: ActiveConnection::new(connection.clone(), session),
        })
    }

    /// Run auth_sigma with automatic BUSY retry.
    /// Attempts a CASE session resumption first; falls back to full SIGMA on failure.
    /// Returns only the Session so that both initial connect and in-place reauth can use it.
    pub async fn auth_sigma_with_busy_retry(
        &self,
        connection: &Arc<dyn ConnectionTrait>,
        node_id: u64,
        controller_id: u64,
    ) -> Result<session::Session> {
        if let Some(ses) = self.try_auth_sigma_resume(connection, node_id, controller_id).await? {
            return Ok(ses);
        }

        const MAX_BUSY_RETRIES: u32 = 5;
        const DEFAULT_BUSY_WAIT: Duration = Duration::from_millis(3000);
        const MAX_BUSY_WAIT: Duration = Duration::from_secs(60);

        let mut busy_retries = 0u32;
        loop {
            match auth_sigma(connection.as_ref(), &self.fabric, self.certmanager.as_ref(), node_id, controller_id).await {
                Ok((ses, resumption)) => {
                    if let Some(record) = resumption {
                        self.resumption.lock().await.insert(node_id, record);
                    }
                    return Ok(ses);
                }
                Err(e) => {
                    if let Some(busy) = e.downcast_ref::<SigmaBusy>() {
                        if busy_retries < MAX_BUSY_RETRIES {
                            let wait = busy.wait_ms
                                .map(|ms| Duration::from_millis(ms.into()))
                                .unwrap_or(DEFAULT_BUSY_WAIT)
                                .min(MAX_BUSY_WAIT);
                            log::info!(
                                "CASE responder BUSY, waiting {:?} before retry ({}/{})",
                                wait, busy_retries + 1, MAX_BUSY_RETRIES
                            );
                            tokio::time::sleep(wait).await;
                            busy_retries += 1;
                            continue;
                        }
                        return Err(e).context(format!(
                            "still BUSY after {} retries", MAX_BUSY_RETRIES
                        ));
                    }
                    return Err(e);
                }
            }
        }
    }

    async fn try_auth_sigma_resume(
        &self,
        connection: &Arc<dyn ConnectionTrait>,
        node_id: u64,
        controller_id: u64,
    ) -> Result<Option<session::Session>> {
        let record = {
            let map = self.resumption.lock().await;
            map.get(&node_id).cloned()
        };
        let record = match record {
            Some(r) => r,
            None => return Ok(None),
        };

        let exchange: u16 = rand::random();
        let session = session::Session::new();
        let mut retrctx = retransmit::RetrContext::new(connection.as_ref(), &session);
        retrctx.subscribe_exchange(exchange);

        let mut ctx = sigma::SigmaContext::new(node_id);
        let ca_pubkey = self.certmanager.get_ca_key()?.public_key().to_sec1_bytes();
        sigma::sigma1_resume(&self.fabric, &mut ctx, &ca_pubkey, &record)?;
        let s1 = messages::sigma1(exchange, &ctx.sigma1_payload)?;

        log::debug!("CASE resume: send Sigma1Resume exchange:{}", exchange);
        retrctx.send(&s1).await?;

        let sigma2 = retrctx.get_next_message().await?;

        // Responder sent a status report instead of Sigma2 / Sigma2Resume - this includes
        // Fall back to full SIGMA in all cases.
        if sigma2.protocol_header.protocol_id == messages::ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL
            && sigma2.protocol_header.opcode == messages::ProtocolMessageHeader::OPCODE_STATUS
        {
            log::debug!(
                "CASE resume: responder rejected with status report, falling back to full SIGMA (exchange:{} {:?})",
                exchange,
                sigma2.status_report_info
            );
            return Ok(None);
        }

        if !sigma::is_sigma2_resume(&sigma2.payload) {
            // Responder gracefully fell back to full Sigma2 - evict the stale record so
            // the next reconnect does a fresh full SIGMA.
            log::debug!("CASE resume: responder sent full Sigma2, falling back");
            self.resumption.lock().await.remove(&node_id);
            return Ok(None);
        }

        let parsed = match sigma::parse_sigma2_resume(&sigma2.payload) {
            Ok(p) => p,
            Err(e) => {
                log::debug!("CASE resume: malformed Sigma2Resume ({:?}), falling back to full SIGMA", e);
                self.resumption.lock().await.remove(&node_id);
                return Ok(None);
            }
        };

        if let Err(e) = sigma::verify_sigma2_resume_mic(
            &record.shared_secret,
            &ctx.initiator_random,
            &parsed.new_resumption_id,
            &parsed.sigma2_resume_mic,
        ) {
            log::debug!("CASE resume: MIC verification failed: {:?}, falling back to full SIGMA", e);
            self.resumption.lock().await.remove(&node_id);
            return Ok(None);
        }

        let sr = messages::status_report_success(exchange)?;
        if let Err(e) = retrctx.send(&sr).await {
            log::debug!("CASE resume: failed to send StatusReport ({:?}), falling back to full SIGMA", e);
            self.resumption.lock().await.remove(&node_id);
            return Ok(None);
        }

        let keypack = sigma::derive_resumed_session_keys(
            &record.shared_secret,
            &ctx.initiator_random,
            &record.resumption_id,
        )?;

        let mut ses = session::Session::new();
        ses.session_id = parsed.responder_session_id;
        ses.my_session_id = ctx.session_id;
        ses.set_decrypt_key(&keypack[16..32]);
        ses.set_encrypt_key(&keypack[..16]);

        let mut local_node = Vec::new();
        local_node.write_u64::<LittleEndian>(controller_id)?;
        ses.local_node = Some(local_node);

        let mut remote_node = Vec::new();
        remote_node.write_u64::<LittleEndian>(node_id)?;
        ses.remote_node = Some(remote_node);

        // Rotate the resumption ID to the one the responder issued for the next round.
        {
            let mut map = self.resumption.lock().await;
            if let Some(entry) = map.get_mut(&node_id) {
                entry.resumption_id = parsed.new_resumption_id;
            }
        }

        log::info!("CASE session resumed for node_id={}", node_id);
        Ok(Some(ses))
    }

    /// Commission a device that is advertising over BLE.
    ///
    /// 1. Scans for a commissionable BLE device with the given `discriminator`.
    /// 2. Runs PASE over BTP (BLE transport protocol).
    /// 3. Pushes the CA cert, signs the device cert (AddNOC).
    /// 4. Sends ArmFailSafe + SetRegulatoryConfig.
    /// 5. Optionally provisions network credentials (Wi-Fi / Thread).
    /// 6. Drops the BLE connection.
    /// 7. Discovers the device on the IP network via mDNS.
    /// 8. Establishes CASE + sends CommissioningComplete over UDP.
    /// 9. Returns an authenticated [`Connection`] ready for commands.
    ///
    /// Requires the `ble` Cargo feature.
    #[cfg(feature = "ble")]
    pub async fn commission_ble(
        &self,
        discriminator: u16,
        short_discriminator: bool,
        pin: u32,
        node_id: u64,
        controller_id: u64,
        network_creds: commission::NetworkCreds,
        mdns: &std::sync::Arc<crate::mdns2::MdnsService>,
    ) -> Result<Connection> {
        use crate::btp::BtpConnection;

        // 1. BLE scan + GATT connect + BTP handshake
        let peripheral = crate::ble::find_by_discriminator(discriminator, short_discriminator, std::time::Duration::from_secs(30))
            .await
            .context("BLE scan")?;
        log::debug!("BLE device found: z2");
        let btp_conn = BtpConnection::connect(peripheral).await.context("BTP connect")?;

        // 2. PASE
        let mut pase_session = auth_spake(btp_conn.as_ref(), pin).await.context("PASE over BLE")?;

        // 3. BLE-side commissioning phase
        commission::commission_ble_phase(
            btp_conn.as_ref(),
            &mut pase_session,
            &self.fabric,
            self.certmanager.as_ref(),
            node_id,
            controller_id,
            &network_creds,
        )
        .await
        .context("BLE commissioning phase")?;
        tokio::time::sleep(std::time::Duration::from_secs(5)).await; // wait for device to finish BLE-side commissioning before dropping connection

        // 4. Drop BTP (BLE connection closes when btp_conn is dropped)
        drop(btp_conn);

        // 5 + 6. Rediscover via operational mDNS and commission over UDP
        for attempt in 0..5 {
            let addresses = match self.discover_operational_addresses(node_id, mdns).await {
                Ok(a) => a,
                Err(e) => {
                    log::debug!("mDNS discovery failed (attempt {}/{}): {:?}", attempt + 1, 5, e);
                    continue;
                }
            };
            for address in &addresses {
                log::debug!("Trying to commission over UDP at {}... (attempt {}/{})", address, attempt + 1, 5);
                let udp_conn = self.transport.create_connection(&address).await;
                let ses = commission::commissioning_complete_udp(
                    udp_conn.as_ref(),
                    self.certmanager.as_ref(),
                    node_id,
                    controller_id,
                    &self.fabric,
                )
                .await;
                if let Ok(ses) = ses {
                    return Ok(Connection {
                        active: ActiveConnection::new(udp_conn, ses),
                    });
                } else {
                    log::debug!("Failed to commission over UDP at {}: {:?}", address, ses.err());
                }
            }
        }
        Err(anyhow::anyhow!("failed to commission device over UDP at any discovered address"))
    }

    #[cfg(feature = "ble")]
    async fn discover_operational_addresses(
        &self,
        node_id: u64,
        mdns: &std::sync::Arc<crate::mdns2::MdnsService>,
    ) -> Result<Vec<String>> {
        use crate::discover;

        let ca_pubkey = self.certmanager.get_ca_public_key()?;
        let fabric_tmp = fabric::Fabric::new(self.fabric.id, 0, &ca_pubkey, &self.certmanager.get_ipk_epoch_key());
        let compressed = fabric_tmp.compressed().context("compressed fabric ID")?;
        let instance = format!("{}-{:016X}", hex::encode_upper(&compressed), node_id);
        let expected_target = format!("{}._matter._tcp.local.", instance);

        log::debug!("Discovering operational device via mDNS with target {}", expected_target);
        let (_, info) = discover::discover_one(
            mdns,
            "_matter._tcp.local",
            "_matter._tcp.local.",
            std::time::Duration::from_secs(120),
            move |target, _| target == expected_target,
        ).await.context(format!("operational mDNS timeout for {}", instance))?;
        log::debug!("Operational mDNS discovered device: {:?}", info);

        let port = info.port.unwrap_or(5540);
        let addresses: Vec<String> = info.ips.iter().map(|ip| {
            if ip.is_ipv6() { format!("[{}]:{}", ip, port) } else { format!("{}:{}", ip, port) }
        }).collect();
        log::info!("Device discovered at {}", addresses.join(", "));
        Ok(addresses)
    }
}

/// Authenticated virtual connection can be used to send commands to device.
impl Connection {
    /// Build a Connection from a transport-layer connection and an established session.
    pub(crate) fn from_parts(conn: Arc<dyn ConnectionTrait>, session: session::Session) -> Self {
        Self { active: ActiveConnection::new(conn, session) }
    }

    /// Read attribute from device and return parsed matter protocol response.
    pub async fn read_request(
        &self,
        endpoint: u16,
        cluster: u32,
        attr: u32,
    ) -> Result<Message> {
        let exchange: u16 = rand::random();
        let msg = messages::im_read_request(endpoint, cluster, attr, exchange)?;
        self.active.request(exchange, &msg).await
    }

    /// Read attribute from device and return tlv with attribute value.
    /// Reassembles chunked reports (MoreChunkedMessages) transparently.
    pub async fn read_request2(
        &self,
        endpoint: u16,
        cluster: u32,
        attr: u32,
    ) -> Result<TlvItemValue> {
        let exchange: u16 = rand::random();
        let msg = messages::im_read_request(endpoint, cluster, attr, exchange)?;
        let mut ex = self.active.open_exchange(exchange);
        ex.send(&msg).await?;
        let report = self.collect_reports(&mut ex).await?;
        let first = report
            .attribute_reports
            .into_iter()
            .next()
            .context("report data contains no attribute reports")?;
        match first.data {
            im::AttributeData::Value(v) => Ok(v),
            im::AttributeData::Status { status, .. } => {
                Err(anyhow::anyhow!("report data with status {}", status))
            }
        }
    }

    /// Receive ReportData chunks on the exchange until the last chunk,
    /// sending the IM StatusResponse between chunks as required, and return
    /// the merged report. The final StatusResponse is only sent when the
    /// device did not set SuppressResponse (e.g. subscribe priming reports).
    async fn collect_reports(&self, exchange: &mut Exchange<'_>) -> Result<im::ReportData> {
        let mut merged: Option<im::ReportData> = None;
        loop {
            let msg = exchange.recv().await?;
            if let Some(status) = &msg.status_report_info {
                return Err(anyhow::anyhow!(
                    "status report while waiting for report data: {:?}",
                    status
                ));
            }
            if msg.protocol_header.protocol_id
                != messages::ProtocolMessageHeader::PROTOCOL_ID_INTERACTION
                || msg.protocol_header.opcode
                    != messages::ProtocolMessageHeader::INTERACTION_OPCODE_REPORT_DATA
            {
                return Err(anyhow::anyhow!(
                    "response is not expected report_data {:?}",
                    msg.protocol_header
                ));
            }
            let report = im::ReportData::parse(&msg.tlv)?;
            let more = report.more_chunks;
            let respond = more || !report.suppress_response;
            match merged.as_mut() {
                Some(m) => m.merge(report),
                None => merged = Some(report),
            }
            if respond {
                let flags = messages::im_status_flags_for(msg.protocol_header.exchange_flags);
                let resp = messages::im_status_response(
                    exchange.id,
                    flags,
                    msg.message_header.message_counter,
                )?;
                exchange.send(&resp).await?;
            }
            if !more {
                return merged.context("no report data received");
            }
        }
    }

    /// Invoke command
    pub async fn invoke_request(
        &self,
        endpoint: u16,
        cluster: u32,
        command: u32,
        payload: &[u8],
    ) -> Result<Message> {
        let exchange: u16 = rand::random();
        log::debug!(
            "invoke_request exch:{} endpoint:{} cluster:{} command:{}",
            exchange,
            endpoint,
            cluster,
            command
        );
        let msg = messages::im_invoke_request(endpoint, cluster, command, exchange, payload, false)?;
        self.active.request(exchange, &msg).await
    }

    /// Invoke command and return result TLV
    pub async fn invoke_request2(
        &self,
        endpoint: u16,
        cluster: u32,
        command: u32,
        payload: &[u8],
    ) -> Result<TlvItemValue> {
        let res = self.invoke_request(endpoint, cluster, command, payload).await?;
        let o = res.tlv.get(&[1, 0, 1, 1]).context("result not found")?;
        Ok(o.clone())
    }

    pub async fn write_request(
        &self,
        endpoint: u16,
        cluster: u32,
        attr: u32,
        payload: &[u8],
    ) -> Result<()> {
        let exchange: u16 = rand::random();
        log::debug!(
            "write_request exch:{} endpoint:{} cluster:{} attr:{}",
            exchange,
            endpoint,
            cluster,
            attr,
        );

        let msg = messages::im_write_request(endpoint, cluster, attr, exchange, payload)?;
        let res = self.active.request(exchange, &msg).await?;
        if res.status_report_info.is_some() {
            return Err(anyhow::anyhow!(
                "write_request failed with status {:?}",
                res.status_report_info
            ))
        };
        if res.protocol_header.protocol_id
            == messages::ProtocolMessageHeader::PROTOCOL_ID_INTERACTION
            && res.protocol_header.opcode
                == messages::ProtocolMessageHeader::INTERACTION_OPCODE_STATUS_RESP
        {
            let stat = res
                .tlv
                .get_int(&[0])
                .context("status not found in status response")?;
            res.tlv.dump(1);
            return Err(anyhow::anyhow!(
                "response is not expected status_resp 0x{:x}",
                stat
            ))
        };
        if res.protocol_header.protocol_id
            != messages::ProtocolMessageHeader::PROTOCOL_ID_INTERACTION
            || res.protocol_header.opcode
                != messages::ProtocolMessageHeader::INTERACTION_OPCODE_WRITE_RESP
        {
            return Err(anyhow::anyhow!(
                "response is not expected write_resp {:?}",
                res.protocol_header
            ))
        };
        let stat = res.tlv.get_int(&[0, 0, 1, 0]).context("status not found in write response")?;
        if stat != 0 {
            return Err(anyhow::anyhow!("write failed with status 0x{:x}", stat));
        }
        Ok(())
    }

    /// Subscribe to attribute changes. `None` path fields act as wildcards.
    /// Set `keep_subscriptions = true` when adding a second subscription on the same
    /// connection so the device does not cancel the first one.
    ///
    /// Handles the full subscribe transaction (chunked priming report, IM
    /// StatusResponse acks, SubscribeResponse) and returns a [Subscription]
    /// delivering decoded updates; updates are acked automatically by the
    /// background read loop.
    pub async fn subscribe_attrs(
        &self,
        endpoint: Option<u16>,
        cluster: Option<u32>,
        attr: Option<u32>,
        keep_subscriptions: bool,
    ) -> Result<Subscription> {
        let exchange: u16 = rand::random();
        log::debug!(
            "subscribe_attrs exch:{} endpoint:{:?} cluster:{:?} attr:{:?} keep:{}",
            exchange, endpoint, cluster, attr, keep_subscriptions
        );
        let msg = messages::im_subscribe_request_attr(endpoint, cluster, attr, exchange, keep_subscriptions)?;
        self.subscribe_internal(exchange, &msg).await
    }

    /// Subscribe to events. `None` path fields act as wildcards.
    /// See [Connection::subscribe_attrs] for transaction details.
    pub async fn subscribe_events(
        &self,
        endpoint: Option<u16>,
        cluster: Option<u32>,
        event: Option<u32>,
        keep_subscriptions: bool,
    ) -> Result<Subscription> {
        let exchange: u16 = rand::random();
        log::debug!(
            "subscribe_events exch:{} endpoint:{:?} cluster:{:?} event:{:?} keep:{}",
            exchange, endpoint, cluster, event, keep_subscriptions
        );
        let msg = messages::im_subscribe_request_event(endpoint, cluster, event, exchange, keep_subscriptions)?;
        self.subscribe_internal(exchange, &msg).await
    }

    async fn subscribe_internal(&self, exchange_id: u16, msg: &[u8]) -> Result<Subscription> {
        let mut exchange = self.active.open_exchange(exchange_id);
        exchange.send(msg).await?;
        let priming = self.collect_reports(&mut exchange).await?;
        let subscription_id = priming
            .subscription_id
            .context("priming report missing subscription id")?;

        // Register before awaiting the SubscribeResponse so no update can be
        // missed; the device cannot report before the transaction completes.
        let rx = self.active.register_subscription(subscription_id);
        let registry = self.active.subscriptions_handle();

        let response = async {
            let resp = exchange.recv().await?;
            if resp.protocol_header.protocol_id
                != messages::ProtocolMessageHeader::PROTOCOL_ID_INTERACTION
                || resp.protocol_header.opcode
                    != messages::ProtocolMessageHeader::INTERACTION_OPCODE_SUBSCRIBE_RESP
            {
                anyhow::bail!(
                    "response is not expected subscribe_resp {:?}",
                    resp.protocol_header
                );
            }
            let sr = im::SubscribeResponse::parse(&resp.tlv)?;
            if sr.subscription_id != subscription_id {
                anyhow::bail!(
                    "subscribe response id {} does not match priming report id {}",
                    sr.subscription_id,
                    subscription_id
                );
            }
            Ok(sr)
        }
        .await;

        match response {
            Ok(sr) => Ok(Subscription {
                subscription_id,
                max_interval: sr.max_interval,
                priming_attribute_reports: priming.attribute_reports,
                priming_event_reports: priming.event_reports,
                rx,
                registry,
            }),
            Err(e) => {
                registry.lock().unwrap().remove(&subscription_id);
                Err(e)
            }
        }
    }

    /// Cancel all subscriptions on this session by sending a SubscribeRequest with
    /// `KeepSubscriptions = false` and no paths. The device drops all prior subscriptions.
    pub async fn im_unsubscribe_all(&self) -> Result<Message> {
        let exchange: u16 = rand::random();
        log::debug!("im_unsubscribe_all exch:{}", exchange);
        let msg = messages::im_unsubscribe_all(exchange)?;
        self.active.request(exchange, &msg).await
    }

    /// Enable or disable automatic IM StatusResponse replies to unsolicited
    /// ReportData (enabled by default). Disable only when acking reports
    /// manually via the raw message API.
    pub fn set_auto_status_response(&self, enabled: bool) {
        self.active.set_auto_status_response(enabled);
    }

    /// Invoke command with timed interaction
    pub async fn invoke_request_timed(
        &self,
        endpoint: u16,
        cluster: u32,
        command: u32,
        payload: &[u8],
        timeout: u16,
    ) -> Result<Message> {
        let exchange: u16 = rand::random();

        // Send timed request first
        let tr = messages::im_timed_request(exchange, timeout)?;
        let result = self.active.request(exchange, &tr).await?;

        if result.protocol_header.protocol_id
            != messages::ProtocolMessageHeader::PROTOCOL_ID_INTERACTION
            || result.protocol_header.opcode
                != messages::ProtocolMessageHeader::INTERACTION_OPCODE_STATUS_RESP
        {
            return Err(anyhow::anyhow!(
                "invoke_request_timed: unexpected response {:?}",
                result
            ));
        }
        let status = result
            .tlv
            .get_int(&[0])
            .context("invoke_request_timed: status not found")?;
        if status != 0 {
            return Err(anyhow::anyhow!(
                "invoke_request_timed: unexpected status {}",
                status
            ));
        }

        log::debug!(
            "invoke_request exch:{} endpoint:{} cluster:{} command:{}",
            exchange,
            endpoint,
            cluster,
            command
        );
        let msg = messages::im_invoke_request(endpoint, cluster, command, exchange, payload, true)?;
        self.active.request(exchange, &msg).await
    }

    /// Receive next unsolicited raw message not handled elsewhere (subscription
    /// reports are delivered decoded via [Subscription]; only reports with an
    /// unknown subscription id and other unsolicited messages end up here).
    /// Returns None when connection is closed. Messages may be dropped when
    /// nobody drains this channel.
    pub async fn recv_event(&self) -> Option<Message> {
        self.active.recv_event().await
    }

    /// Try receive event without blocking.
    pub fn try_recv_event(&self) -> Option<Message> {
        self.active.try_recv_event()
    }

    /// Re-run CASE over the existing transport channel without tearing it down.
    /// Stops the active read loop, runs auth_sigma (with BUSY retry), swaps the session,
    /// and restarts the read loop -- all on the same underlying UDP channel registration.
    pub async fn reauth(
        &self,
        controller: &Controller,
        node_id: u64,
        controller_id: u64,
    ) -> Result<()> {
        self.active.pause_read_loop().await;
        let new_session = controller
            .auth_sigma_with_busy_retry(&self.active.transport_conn, node_id, controller_id)
            .await?;
        self.active.reauth_with_session(new_session).await
    }
}

/// Active subscription created by [Connection::subscribe_attrs] or
/// [Connection::subscribe_events]. Decoded updates are delivered via [Subscription::next];
/// the background read loop acks them automatically. Dropping the handle stops
/// delivery (the device-side subscription stays active until it expires or is
/// cancelled via [Connection::im_unsubscribe_all]).
pub struct Subscription {
    pub subscription_id: u32,
    /// Maximum reporting interval in seconds granted by the device.
    pub max_interval: u16,
    /// Attribute reports from the priming report (current values at subscribe time).
    pub priming_attribute_reports: Vec<im::AttributeReport>,
    /// Event reports from the priming report.
    pub priming_event_reports: Vec<im::EventReport>,
    rx: mpsc::Receiver<im::ReportUpdate>,
    registry: Arc<std::sync::Mutex<HashMap<u32, mpsc::Sender<im::ReportUpdate>>>>,
}

impl Subscription {
    /// Receive the next decoded update. Returns None when the connection is
    /// closed or re-authenticated (the subscription is then gone; resubscribe).
    pub async fn next(&mut self) -> Option<im::ReportUpdate> {
        self.rx.recv().await
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.registry.lock().unwrap().remove(&self.subscription_id);
    }
}

pub fn pin_to_passcode(pin: u32) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.write_u32::<LittleEndian>(pin)?;
    Ok(out)
}

pub(crate) async fn auth_spake(connection: &dyn ConnectionTrait, pin: u32) -> Result<session::Session> {
    let exchange = rand::random();
    log::debug!("start auth_spake");
    let mut session = session::Session::new();
    session.my_session_id = 1;
    let mut retrctx = retransmit::RetrContext::new(connection, &session);
    // send pbkdf
    log::debug!("send pbkdf request");
    let pbkdf_req_protocol_message = messages::pbkdf_req(exchange)?;
    retrctx.send(&pbkdf_req_protocol_message).await?;

    // get pbkdf response
    let pbkdf_response = retrctx.get_next_message().await?;
    if pbkdf_response.protocol_header.protocol_id
        != messages::ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL
        || pbkdf_response.protocol_header.opcode
            != messages::ProtocolMessageHeader::OPCODE_PBKDF_RESP
    {
        return Err(anyhow::anyhow!("pbkdf response not received"));
    }

    let iterations = pbkdf_response
        .tlv
        .get_int(&[4, 1])
        .context("pbkdf_response - iterations missing")?;
    let salt = pbkdf_response
        .tlv
        .get_octet_string(&[4, 2])
        .context("pbkdf_response - salt missing")?;
    let p_session = pbkdf_response
        .tlv
        .get_int(&[3])
        .context("pbkdf_response - session missing")?;

    // send pake1
    let engine = spake2p::Engine::new()?;
    let mut ctx = engine.start(&pin_to_passcode(pin)?, salt, iterations as u32)?;
    log::debug!("send pake1 request");
    let pake1_protocol_message = messages::pake1(exchange, ctx.x.as_bytes(), -1)?;
    retrctx.send(&pake1_protocol_message).await?;

    // receive pake2
    let pake2 = retrctx.get_next_message().await?;
    if pake2.protocol_header.protocol_id
        != messages::ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL
        || pake2.protocol_header.opcode != messages::ProtocolMessageHeader::OPCODE_PASE_PAKE2
    {
        return Err(anyhow::anyhow!("pake2 not received"));
    }
    let pake2_pb = pake2
        .tlv
        .get_octet_string(&[1])
        .context("pake2 pb tlv missing")?;
    ctx.y = p256::EncodedPoint::from_bytes(pake2_pb)?;

    let pake2_cb = pake2
        .tlv
        .get_octet_string(&[2])
        .context("pake2 cb tlv missing")?;

    // send pake3
    let mut hash_seed = "CHIP PAKE V1 Commissioning".as_bytes().to_vec();
    hash_seed.extend_from_slice(&pbkdf_req_protocol_message[6..]);
    hash_seed.extend_from_slice(&pbkdf_response.payload);
    engine.finish(&mut ctx, &hash_seed, pake2_cb)?;
    let pake3_protocol_message = messages::pake3(
        exchange,
        &ctx.ca.context("ca value not present in context")?,
        -1,
    )?;
    log::debug!("send pake3 request");
    retrctx.send(&pake3_protocol_message).await?;

    let pake3_resp = retrctx.get_next_message().await?;
    match &pake3_resp.status_report_info {
        Some(s) => {
            if !s.is_ok() {
                return Err(anyhow::anyhow!("pake3 resp not ok), got {:?}", pake3_resp));
            }
        }
        None => {
            return Err(anyhow::anyhow!(
                "expecting status report (pake3 resp), got {:?}",
                pake3_resp
            ))
        }
    }

    session.set_encrypt_key(&ctx.encrypt_key.context("encrypt key missing")?);
    session.set_decrypt_key(&ctx.decrypt_key.context("decrypt key missing")?);
    session.session_id = p_session as u16;
    log::debug!("auth_spake ok; session: {}", session.session_id);
    Ok(session)
}

pub(crate) async fn auth_sigma(
    connection: &dyn ConnectionTrait,
    fabric: &fabric::Fabric,
    cm: &dyn certmanager::CertManager,
    node_id: u64,
    controller_id: u64,
) -> Result<(session::Session, Option<sigma::ResumptionRecord>)> {
    log::debug!("auth_sigma");
    let exchange = rand::random();
    let session = session::Session::new();
    let mut retrctx = retransmit::RetrContext::new(connection, &session);
    retrctx.subscribe_exchange(exchange);
    let mut ctx = sigma::SigmaContext::new(node_id);
    let ca_pubkey = cm.get_ca_key()?.public_key().to_sec1_bytes();
    sigma::sigma1(fabric, &mut ctx, &ca_pubkey)?;
    let s1 = messages::sigma1(exchange, &ctx.sigma1_payload)?;

    log::debug!("send sigma1 {}", exchange);
    retrctx.send(&s1).await?;

    // receive sigma2
    log::debug!("receive sigma2 {}", exchange);
    let sigma2 = retrctx.get_next_message().await?;
    log::debug!("sigma2 received {:?}", sigma2);
    if sigma2.protocol_header.protocol_id == messages::ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL
        && sigma2.protocol_header.opcode == messages::ProtocolMessageHeader::OPCODE_STATUS
    {
        let sri = sigma2.status_report_info.context("status report info missing")?;
        if sri.is_busy() {
            return Err(anyhow::Error::new(SigmaBusy { wait_ms: sri.minimum_wait_time_ms() }));
        }
        return Err(anyhow::anyhow!("sigma2 not received, status: {}", sri));
    }
    ctx.sigma2_payload = sigma2.payload;
    ctx.responder_session = sigma2
        .tlv
        .get_int(&[2])
        .context("responder session tlv missing in sigma2")? as u16;
    ctx.responder_public = sigma2
        .tlv
        .get_octet_string(&[3])
        .context("responder public tlv missing in sigma2")?
        .to_vec();

    log::debug!("verify sigma2 {}", exchange);
    let resumption_id =
        sigma::verify_sigma2(fabric, &ctx, &ca_pubkey).context("sigma2 verification failed")?;

    let controller_private = cm.get_user_key(controller_id)?;
    let controller_x509 = cm.get_user_cert(controller_id)?;
    let controller_matter_cert =
        cert_matter::convert_x509_bytes_to_matter(&controller_x509, &ca_pubkey)?;

    // send sigma3
    log::debug!("send sigma3 {} with piggyback ack for {}", exchange, sigma2.message_header.message_counter);
    sigma::sigma3(
        fabric,
        &mut ctx,
        &controller_private.to_sec1_der()?,
        &controller_matter_cert,
    )?;
    let sigma3 = messages::sigma3(exchange, &ctx.sigma3_payload, sigma2.message_header.message_counter)?;
    retrctx.send(&sigma3).await?;

    log::debug!("receive result {}", exchange);
    let status = retrctx.get_next_message().await?;
    if !status
        .status_report_info
        .as_ref()
        .context("sigma3 status resp not received")?
        .is_ok()
    {
        return Err(anyhow::anyhow!(format!(
            "response to sigma3 does not contain status ok {:?}",
            status
        )));
    }

    //session keys
    let mut th = ctx.sigma1_payload.clone();
    th.extend_from_slice(&ctx.sigma2_payload);

    let mut transcript = th;
    transcript.extend_from_slice(&ctx.sigma3_payload);
    let transcript_hash = cryptoutil::sha256(&transcript);
    let mut salt = fabric.signed_ipk()?;
    salt.extend_from_slice(&transcript_hash);
    let shared = ctx.shared.context("shared secret not in context")?;
    let shared_bytes: [u8; 32] = shared.raw_secret_bytes().as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("shared secret wrong length"))?;
    let keypack = cryptoutil::hkdf_sha256(
        &salt,
        &shared_bytes,
        "SessionKeys".as_bytes(),
        16 * 3,
    )?;
    let mut ses = session::Session::new();
    ses.session_id = ctx.responder_session;
    ses.my_session_id = ctx.session_id;
    ses.set_decrypt_key(&keypack[16..32]);
    ses.set_encrypt_key(&keypack[..16]);

    let mut local_node = Vec::new();
    local_node.write_u64::<LittleEndian>(controller_id)?;
    ses.local_node = Some(local_node);

    let mut remote_node = Vec::new();
    remote_node.write_u64::<LittleEndian>(node_id)?;
    ses.remote_node = Some(remote_node);

    let resumption = resumption_id
        .map(|id| sigma::ResumptionRecord { resumption_id: id, shared_secret: shared_bytes });

    if resumption.is_none() {
        log::debug!("auth_sigma: responder did not include a NewResumptionID - resumption unavailable for node {}", node_id);
    }

    Ok((ses, resumption))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::ProtocolMessageHeader;
    use crate::tlv;
    use std::time::Duration;

    // Loopback transport: the test acts as the device on the other end.
    struct MockConn {
        inbound: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
        outbound: mpsc::UnboundedSender<Vec<u8>>,
        reliable: bool,
        mrp: std::sync::Mutex<crate::mrp::MrpParameters>,
    }

    #[async_trait::async_trait]
    impl ConnectionTrait for MockConn {
        async fn send(&self, data: &[u8]) -> Result<()> {
            self.outbound
                .send(data.to_vec())
                .map_err(|_| anyhow::anyhow!("mock closed"))
        }
        async fn receive(&self, timeout: Duration) -> Result<Vec<u8>> {
            let mut rx = self.inbound.lock().await;
            match tokio::time::timeout(timeout, rx.recv()).await {
                Ok(Some(d)) => Ok(d),
                Ok(None) => Err(anyhow::anyhow!("mock closed")),
                Err(_) => Err(anyhow::anyhow!("timeout")),
            }
        }
        fn is_reliable(&self) -> bool {
            self.reliable
        }
        fn mrp_params(&self) -> crate::mrp::MrpParameters {
            *self.mrp.lock().unwrap()
        }
        fn set_mrp_params(&self, params: crate::mrp::MrpParameters) {
            *self.mrp.lock().unwrap() = params;
        }
    }

    struct MockDevice {
        rx: mpsc::UnboundedReceiver<Vec<u8>>,
        tx: mpsc::Sender<Vec<u8>>,
        session: session::Session,
    }

    impl MockDevice {
        async fn recv(&mut self) -> Message {
            let data = tokio::time::timeout(Duration::from_secs(2), self.rx.recv())
                .await
                .expect("timeout waiting for controller message")
                .expect("mock closed");
            Message::decode(&data).unwrap()
        }

        async fn expect_status_response(&mut self, want_flags: u8, want_ack: u32) {
            let msg = self.recv().await;
            assert_eq!(
                msg.protocol_header.protocol_id,
                ProtocolMessageHeader::PROTOCOL_ID_INTERACTION
            );
            assert_eq!(
                msg.protocol_header.opcode,
                ProtocolMessageHeader::INTERACTION_OPCODE_STATUS_RESP
            );
            assert_eq!(
                msg.protocol_header.exchange_flags,
                ProtocolMessageHeader::FLAG_RELIABILITY | want_flags
            );
            assert_eq!(msg.protocol_header.ack_counter, want_ack);
            assert_eq!(msg.tlv.get_int(&[0]), Some(0));
        }

        async fn expect_silence(&mut self) {
            assert!(
                tokio::time::timeout(Duration::from_millis(200), self.rx.recv())
                    .await
                    .is_err(),
                "unexpected message from controller"
            );
        }

        async fn send(&self, payload: &[u8]) -> u32 {
            let encoded = self.session.encode_message(payload).unwrap();
            let (header, _) = messages::MessageHeader::decode(&encoded).unwrap();
            self.tx.send(encoded).await.unwrap();
            header.message_counter
        }

        async fn recv_within(&mut self, d: Duration) -> Option<Message> {
            match tokio::time::timeout(d, self.rx.recv()).await {
                Ok(Some(data)) => Some(Message::decode(&data).unwrap()),
                _ => None,
            }
        }
    }

    fn mock_pair() -> (Connection, MockDevice) {
        mock_pair_with(true, Default::default())
    }

    fn mock_pair_unreliable(mrp: crate::mrp::MrpParameters) -> (Connection, MockDevice) {
        mock_pair_with(false, mrp)
    }

    fn mock_pair_with(reliable: bool, mrp: crate::mrp::MrpParameters) -> (Connection, MockDevice) {
        let (to_ctrl_tx, to_ctrl_rx) = mpsc::channel(32);
        let (to_dev_tx, to_dev_rx) = mpsc::unbounded_channel();
        let mock = Arc::new(MockConn {
            inbound: tokio::sync::Mutex::new(to_ctrl_rx),
            outbound: to_dev_tx,
            reliable,
            mrp: std::sync::Mutex::new(mrp),
        });
        let conn = Connection::from_parts(mock, session::Session::new());
        let device = MockDevice {
            rx: to_dev_rx,
            tx: to_ctrl_tx,
            session: session::Session::new(),
        };
        (conn, device)
    }

    fn report_data(
        exchange: u16,
        flags: u8,
        sub_id: Option<u32>,
        values: &[(u16, bool)],
        more: bool,
        suppress: bool,
    ) -> Vec<u8> {
        let b = ProtocolMessageHeader {
            exchange_flags: flags,
            opcode: ProtocolMessageHeader::INTERACTION_OPCODE_REPORT_DATA,
            exchange_id: exchange,
            protocol_id: ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
            ack_counter: 0,
        }
        .encode()
        .unwrap();
        let mut t = tlv::TlvBuffer::from_vec(b);
        t.write_anon_struct().unwrap();
        if let Some(id) = sub_id {
            t.write_uint32(0, id).unwrap();
        }
        t.write_array(1).unwrap();
        for (endpoint, value) in values {
            t.write_anon_struct().unwrap();
            t.write_struct(1).unwrap();
            t.write_uint32(0, 0).unwrap();
            t.write_list(1).unwrap();
            t.write_uint16(2, *endpoint).unwrap();
            t.write_uint32(3, 6).unwrap();
            t.write_uint32(4, 0).unwrap();
            t.write_struct_end().unwrap();
            t.write_bool(2, *value).unwrap();
            t.write_struct_end().unwrap();
            t.write_struct_end().unwrap();
        }
        t.write_struct_end().unwrap();
        if more {
            t.write_bool(3, true).unwrap();
        }
        if suppress {
            t.write_bool(4, true).unwrap();
        }
        t.write_struct_end().unwrap();
        t.data
    }

    fn subscribe_response(exchange: u16, sub_id: u32, max_interval: u16) -> Vec<u8> {
        let b = ProtocolMessageHeader {
            exchange_flags: 0,
            opcode: ProtocolMessageHeader::INTERACTION_OPCODE_SUBSCRIBE_RESP,
            exchange_id: exchange,
            protocol_id: ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
            ack_counter: 0,
        }
        .encode()
        .unwrap();
        let mut t = tlv::TlvBuffer::from_vec(b);
        t.write_anon_struct().unwrap();
        t.write_uint32(0, sub_id).unwrap();
        t.write_uint16(2, max_interval).unwrap();
        t.write_struct_end().unwrap();
        t.data
    }

    const FLAGS_RESPONDER: u8 = 0;
    const FLAGS_DEVICE_INITIATED: u8 = ProtocolMessageHeader::FLAG_INITIATOR;
    const ACK_AND_INITIATOR: u8 =
        ProtocolMessageHeader::FLAG_INITIATOR | ProtocolMessageHeader::FLAG_ACK;

    #[tokio::test]
    async fn test_read_request2_single_chunk() {
        let (conn, mut device) = mock_pair();
        let task = tokio::spawn(async move {
            let req = device.recv().await;
            assert_eq!(
                req.protocol_header.opcode,
                ProtocolMessageHeader::INTERACTION_OPCODE_READ_REQ
            );
            let exchange = req.protocol_header.exchange_id;
            device
                .send(&report_data(exchange, FLAGS_RESPONDER, None, &[(1, true)], false, true))
                .await;
            device.expect_silence().await;
        });
        let val = conn.read_request2(1, 6, 0).await.unwrap();
        assert_eq!(val, TlvItemValue::Bool(true));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn test_read_request2_chunked() {
        let (conn, mut device) = mock_pair();
        let task = tokio::spawn(async move {
            let req = device.recv().await;
            let exchange = req.protocol_header.exchange_id;
            let counter = device
                .send(&report_data(exchange, FLAGS_RESPONDER, None, &[(1, true)], true, false))
                .await;
            device.expect_status_response(ACK_AND_INITIATOR, counter).await;
            device
                .send(&report_data(exchange, FLAGS_RESPONDER, None, &[(2, false)], false, true))
                .await;
            device.expect_silence().await;
        });
        let val = conn.read_request2(1, 6, 0).await.unwrap();
        assert_eq!(val, TlvItemValue::Bool(true));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn test_subscribe_and_updates() {
        let (conn, mut device) = mock_pair();
        let task = tokio::spawn(async move {
            let req = device.recv().await;
            assert_eq!(
                req.protocol_header.opcode,
                ProtocolMessageHeader::INTERACTION_OPCODE_SUBSCRIBE_REQ
            );
            let exchange = req.protocol_header.exchange_id;
            let counter = device
                .send(&report_data(exchange, FLAGS_RESPONDER, Some(7), &[(1, true)], true, false))
                .await;
            device.expect_status_response(ACK_AND_INITIATOR, counter).await;
            let counter = device
                .send(&report_data(exchange, FLAGS_RESPONDER, Some(7), &[(2, false)], false, false))
                .await;
            device.expect_status_response(ACK_AND_INITIATOR, counter).await;
            device.send(&subscribe_response(exchange, 7, 60)).await;

            // device-initiated update on a fresh exchange
            let counter = device
                .send(&report_data(0x4001, FLAGS_DEVICE_INITIATED, Some(7), &[(1, false)], false, false))
                .await;
            device
                .expect_status_response(ProtocolMessageHeader::FLAG_ACK, counter)
                .await;
            device
        });

        let mut sub = conn.subscribe_attrs(Some(1), Some(6), Some(0), false).await.unwrap();
        assert_eq!(sub.subscription_id, 7);
        assert_eq!(sub.max_interval, 60);
        assert_eq!(sub.priming_attribute_reports.len(), 2);
        assert_eq!(sub.priming_attribute_reports[0].path.endpoint, Some(1));
        assert_eq!(sub.priming_attribute_reports[1].path.endpoint, Some(2));

        let update = sub.next().await.unwrap();
        assert_eq!(update.subscription_id, 7);
        assert_eq!(update.attribute_reports.len(), 1);
        assert_eq!(
            update.attribute_reports[0].data,
            im::AttributeData::Value(TlvItemValue::Bool(false))
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn test_chunked_unsolicited_report() {
        let (conn, mut device) = mock_pair();
        let task = tokio::spawn(async move {
            let req = device.recv().await;
            let exchange = req.protocol_header.exchange_id;
            let counter = device
                .send(&report_data(exchange, FLAGS_RESPONDER, Some(9), &[(1, true)], false, false))
                .await;
            device.expect_status_response(ACK_AND_INITIATOR, counter).await;
            device.send(&subscribe_response(exchange, 9, 60)).await;

            // chunked device-initiated update
            let counter = device
                .send(&report_data(0x4002, FLAGS_DEVICE_INITIATED, Some(9), &[(1, false)], true, false))
                .await;
            device
                .expect_status_response(ProtocolMessageHeader::FLAG_ACK, counter)
                .await;
            let counter = device
                .send(&report_data(0x4002, FLAGS_DEVICE_INITIATED, Some(9), &[(2, true)], false, false))
                .await;
            device
                .expect_status_response(ProtocolMessageHeader::FLAG_ACK, counter)
                .await;
        });

        let mut sub = conn.subscribe_attrs(Some(1), Some(6), Some(0), false).await.unwrap();
        let update = sub.next().await.unwrap();
        assert_eq!(update.attribute_reports.len(), 2);
        assert_eq!(update.attribute_reports[0].path.endpoint, Some(1));
        assert_eq!(update.attribute_reports[1].path.endpoint, Some(2));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn test_unregistered_subscription_id() {
        let (conn, mut device) = mock_pair();

        let counter = device
            .send(&report_data(0x4003, FLAGS_DEVICE_INITIATED, Some(99), &[(1, true)], false, false))
            .await;
        device
            .expect_status_response(ProtocolMessageHeader::FLAG_ACK, counter)
            .await;
        let raw = conn.recv_event().await.unwrap();
        assert_eq!(
            raw.protocol_header.opcode,
            ProtocolMessageHeader::INTERACTION_OPCODE_REPORT_DATA
        );

        conn.set_auto_status_response(false);
        device
            .send(&report_data(0x4004, FLAGS_DEVICE_INITIATED, Some(99), &[(1, true)], false, false))
            .await;
        device.expect_silence().await;
        let raw = conn.recv_event().await.unwrap();
        assert_eq!(raw.protocol_header.exchange_id, 0x4004);
    }

    #[tokio::test]
    async fn test_duplicate_message_dropped() {
        let (conn, mut device) = mock_pair();

        let payload =
            report_data(0x4005, FLAGS_DEVICE_INITIATED, Some(99), &[(1, true)], false, false);
        let encoded = device.session.encode_message(&payload).unwrap();
        let (header, _) = messages::MessageHeader::decode(&encoded).unwrap();
        device.tx.send(encoded.clone()).await.unwrap();
        device
            .expect_status_response(ProtocolMessageHeader::FLAG_ACK, header.message_counter)
            .await;
        let raw = conn.recv_event().await.unwrap();
        assert_eq!(raw.protocol_header.exchange_id, 0x4005);

        // replayed frame must be dropped: no status response, no event
        device.tx.send(encoded).await.unwrap();
        device.expect_silence().await;
        assert!(conn.try_recv_event().is_none());
    }

    #[tokio::test]
    async fn test_initiator_flag_not_misrouted() {
        let (conn, mut device) = mock_pair();
        let task = tokio::spawn(async move {
            let req = device.recv().await;
            let exchange = req.protocol_header.exchange_id;
            // device-initiated report colliding with the pending exchange id
            // must not resolve the pending read request
            let counter = device
                .send(&report_data(exchange, FLAGS_DEVICE_INITIATED, None, &[(5, false)], false, false))
                .await;
            device
                .expect_status_response(ProtocolMessageHeader::FLAG_ACK, counter)
                .await;
            device
                .send(&report_data(exchange, FLAGS_RESPONDER, None, &[(1, true)], false, true))
                .await;
        });
        let val = conn.read_request2(1, 6, 0).await.unwrap();
        assert_eq!(val, TlvItemValue::Bool(true));
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn test_retransmit_schedule_and_give_up() {
        let mrp = crate::mrp::MrpParameters::from_txt_ms(Some(5000), None, None);
        let (conn, mut device) = mock_pair_unreliable(mrp);
        let req = tokio::spawn(async move { conn.read_request2(1, 6, 0).await });

        let mut times = Vec::new();
        let mut counters = Vec::new();
        for i in 0..crate::mrp::MRP_MAX_TRANSMISSIONS {
            let msg = device
                .recv_within(Duration::from_secs(30))
                .await
                .unwrap_or_else(|| panic!("missing transmission {}", i));
            times.push(tokio::time::Instant::now());
            counters.push(msg.message_header.message_counter);
        }
        assert!(counters.iter().all(|c| *c == counters[0]));

        // gap n follows backoff: 5s * 1.1 * 1.6^max(0, n-1) plus up to 25% jitter
        for (n, w) in times.windows(2).enumerate() {
            let gap = (w[1] - w[0]).as_secs_f64();
            let lower = 5.0 * 1.1 * 1.6f64.powi(n.saturating_sub(1) as i32);
            let upper = lower * 1.25;
            assert!(
                gap >= lower - 0.01 && gap <= upper + 0.1,
                "gap {} = {} not in [{}, {}]",
                n, gap, lower, upper
            );
        }

        // after the final backoff period the exchange is dropped and the request fails
        let res = req.await.unwrap();
        assert!(res.is_err(), "request should fail after give-up");
        assert!(
            device.recv_within(Duration::from_secs(120)).await.is_none(),
            "no transmissions expected after give-up"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_retransmit_stops_after_ack() {
        let (conn, mut device) = mock_pair_unreliable(Default::default());
        let _req = tokio::spawn(async move { conn.read_request2(1, 6, 0).await });

        let msg = device.recv_within(Duration::from_secs(5)).await.expect("request");
        let retr = device.recv_within(Duration::from_secs(5)).await.expect("retransmit");
        assert_eq!(
            msg.message_header.message_counter,
            retr.message_header.message_counter
        );

        device
            .send(&messages::ack(
                msg.protocol_header.exchange_id,
                msg.message_header.message_counter as i64,
            ).unwrap())
            .await;
        assert!(
            device.recv_within(Duration::from_secs(60)).await.is_none(),
            "no retransmissions expected after ack"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_retransmit_not_starved_by_inbound_traffic() {
        let (conn, mut device) = mock_pair_unreliable(Default::default());
        let _req = tokio::spawn(async move { conn.read_request2(1, 6, 0).await });

        let first = device.recv_within(Duration::from_secs(2)).await.expect("request");
        let counter = first.message_header.message_counter;

        // keep the read loop busy with inbound messages so it never hits a
        // receive timeout; the retransmit (due at ~550-690ms) must still fire
        let mut seen_retransmit = false;
        for _ in 0..10 {
            device.send(&messages::ack(0x7777, 999_999).unwrap()).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            while let Ok(data) = device.rx.try_recv() {
                let m = Message::decode(&data).unwrap();
                if m.message_header.message_counter == counter {
                    seen_retransmit = true;
                }
            }
        }
        assert!(seen_retransmit, "retransmit starved by continuous inbound traffic");
    }
}
