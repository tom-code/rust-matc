use std::{sync::Arc, time::Duration};

use crate::{
    active_connection::ActiveConnection,
    cert_matter, certmanager, commission, fabric,
    messages::{self, Message},
    retransmit, session, sigma, spake2p,
    tlv::TlvItemValue,
    transport::{self, ConnectionTrait},
    util::cryptoutil,
};
use anyhow::{Context, Result};
use byteorder::{LittleEndian, WriteBytesExt};

pub struct Controller {
    certmanager: Arc<dyn certmanager::CertManager>,
    #[allow(dead_code)]
    transport: Arc<transport::Transport>,
    fabric: fabric::Fabric,
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
        let fabric = fabric::Fabric::new(fabric_id, CA_ID, &certmanager.get_ca_public_key()?);
        Ok(Arc::new(Self {
            certmanager: certmanager.clone(),
            transport: transport.clone(),
            fabric,
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
        let session = auth_sigma(
            connection.as_ref(),
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

    /// Run auth_sigma with automatic BUSY retry.
    /// Returns only the Session so that both initial connect and in-place reauth can use it.
    pub async fn auth_sigma_with_busy_retry(
        &self,
        connection: &Arc<dyn ConnectionTrait>,
        node_id: u64,
        controller_id: u64,
    ) -> Result<session::Session> {
        const MAX_BUSY_RETRIES: u32 = 5;
        const DEFAULT_BUSY_WAIT: Duration = Duration::from_millis(3000);
        const MAX_BUSY_WAIT: Duration = Duration::from_secs(60);

        let mut busy_retries = 0u32;
        loop {
            match auth_sigma(connection.as_ref(), &self.fabric, self.certmanager.as_ref(), node_id, controller_id).await {
                Ok(ses) => return Ok(ses),
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
        mdns_receiver: &tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<crate::mdns2::MdnsEvent>>,
    ) -> Result<Connection> {
        use crate::{btp::BtpConnection, discover};

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

        // 4. Drop BTP (BLE connection closes when btp_conn is dropped)
        drop(btp_conn);

        // 5. Rediscover device via operational mDNS
        let ca_pubkey = self.certmanager.get_ca_public_key()?;
        let fabric_tmp = fabric::Fabric::new(self.fabric.id, 0, &ca_pubkey);
        let compressed = fabric_tmp.compressed().context("compressed fabric ID")?;
        let instance = format!("{}-{:016X}", hex::encode_upper(&compressed), node_id);
        let expected_target = format!("{}._matter._tcp.local.", instance);

        let mut addresses = Vec::new();
        {
            let mut rx = mdns_receiver.lock().await;
            mdns.active_lookup("_matter._tcp.local", 0xff).await;
            loop {
                match tokio::time::timeout(std::time::Duration::from_secs(30), rx.recv()).await {
                    Ok(Some(crate::mdns2::MdnsEvent::ServiceDiscovered { name, records: _, target })) => {
                        if name != "_matter._tcp.local." || target != expected_target {
                            continue;
                        }
                        let info = discover::extract_matter_info(&target, mdns).await?;
                        log::debug!("Operational mDNS discovered device: {:?}", info);

                        let port = info.port.unwrap_or(5540);
                        for ip in &info.ips {
                            if ip.is_ipv6() {
                                addresses.push(format!("[{}]:{}", ip, port));
                            } else {
                                addresses.push(format!("{}:{}", ip, port));
                            }
                        }
                        break;
                    }
                    Ok(_) => continue,
                    Err(_) => anyhow::bail!("operational mDNS timeout for {}", instance),
                }
            }
        };

        log::info!("Device discovered at {}", addresses.join(", "));

        // 6. UDP connection + CASE + CommissioningComplete
        for address in addresses {
            log::debug!("Trying to commission over UDP at {}...", address);
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
        Err(anyhow::anyhow!("failed to commission device over UDP at any discovered address"))
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
    pub async fn read_request2(
        &self,
        endpoint: u16,
        cluster: u32,
        attr: u32,
    ) -> Result<TlvItemValue> {
        let res = self.read_request(endpoint, cluster, attr).await?;
        if (res.protocol_header.protocol_id
            != messages::ProtocolMessageHeader::PROTOCOL_ID_INTERACTION)
            || (res.protocol_header.opcode
                != messages::ProtocolMessageHeader::INTERACTION_OPCODE_REPORT_DATA)
        {
            Err(anyhow::anyhow!(
                "response is not expected report_data {:?}",
                res.protocol_header
            ))
        } else {
            match res.tlv.get(&[1, 0, 1, 2]) {
                Some(a) => Ok(a.clone()),
                None => {
                    let s = res
                        .tlv
                        .get(&[1, 0, 0, 1, 0])
                        .context("report data format not recognized1")?;
                    if let TlvItemValue::Int(status) = s {
                        Err(anyhow::anyhow!("report data with status {}", status))
                    } else {
                        Err(anyhow::anyhow!("report data format not recognized2"))
                    }
                }
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

    pub async fn im_subscribe_request(
        &self,
        endpoint: u16,
        cluster: u32,
        event: u32,
    ) -> Result<Message> {
        let exchange: u16 = rand::random();
        log::debug!(
            "im_subscribe_request exch:{} endpoint:{} cluster:{} event:{}",
            exchange,
            endpoint,
            cluster,
            event
        );
        let msg = messages::im_subscribe_request(endpoint, cluster, exchange, event)?;
        self.active.request(exchange, &msg).await
    }

    /// Subscribe to attribute changes. Returns the initial ReportData message.
    /// Set `keep_subscriptions = true` when adding a second subscription on the same
    /// connection so the device does not cancel the first one.
    pub async fn im_subscribe_request_attr(
        &self,
        endpoint: u16,
        cluster: u32,
        attr: u32,
        keep_subscriptions: bool,
    ) -> Result<Message> {
        let exchange: u16 = rand::random();
        log::debug!(
            "im_subscribe_request_attr exch:{} endpoint:{} cluster:{} attr:{} keep:{}",
            exchange, endpoint, cluster, attr, keep_subscriptions
        );
        let msg = messages::im_subscribe_request_attr(endpoint, cluster, attr, exchange, keep_subscriptions)?;
        self.active.request(exchange, &msg).await
    }

    /// Cancel all subscriptions on this session by sending a SubscribeRequest with
    /// `KeepSubscriptions = false` and no paths. The device drops all prior subscriptions.
    pub async fn im_unsubscribe_all(&self) -> Result<Message> {
        let exchange: u16 = rand::random();
        log::debug!("im_unsubscribe_all exch:{}", exchange);
        let msg = messages::im_unsubscribe_all(exchange)?;
        self.active.request(exchange, &msg).await
    }

    pub async fn im_status_response(
        &self,
        exchange: u16,
        flags: u8,
        ack: u32
    ) -> Result<()> {
        let msg = messages::im_status_response(exchange, flags, ack)?;
        self.active.send(&msg).await
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

    /// Receive next event (for subscriptions). Returns None when connection is closed.
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
        let new_session = controller
            .auth_sigma_with_busy_retry(&self.active.transport_conn, node_id, controller_id)
            .await?;
        self.active.reauth_with_session(new_session).await
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
) -> Result<session::Session> {
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
    let keypack = cryptoutil::hkdf_sha256(
        &salt,
        shared.raw_secret_bytes().as_slice(),
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

    Ok(ses)
}

