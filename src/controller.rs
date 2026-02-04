use std::sync::Arc;

use crate::{
    active_connection::ActiveConnection,
    cert_matter, certmanager, commission, fabric,
    messages::{self, Message},
    retransmit, session, sigma, spake2p,
    tlv::TlvItemValue,
    transport,
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
        connection: &Arc<transport::Connection>,
        pin: u32,
        node_id: u64,
        controller_id: u64,
    ) -> Result<Connection> {
        let mut session = auth_spake(connection, pin).await?;
        let session = commission::commission(
            connection,
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
        connection: &Arc<transport::Connection>,
        node_id: u64,
        controller_id: u64,
    ) -> Result<Connection> {
        let session = auth_sigma(
            connection,
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
}

/// Authenticated virtual connection can be used to send commands to device.
impl Connection {
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
}

pub fn pin_to_passcode(pin: u32) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.write_u32::<LittleEndian>(pin)?;
    Ok(out)
}

async fn auth_spake(connection: &transport::Connection, pin: u32) -> Result<session::Session> {
    let exchange = rand::random();
    log::debug!("start auth_spake");
    let mut session = session::Session::new();
    let mut retrctx = retransmit::RetrContext::new(connection, &mut session);
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

    // send pake3
    let mut hash_seed = "CHIP PAKE V1 Commissioning".as_bytes().to_vec();
    hash_seed.extend_from_slice(&pbkdf_req_protocol_message[6..]);
    hash_seed.extend_from_slice(&pbkdf_response.payload);
    engine.finish(&mut ctx, &hash_seed)?;
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
    connection: &transport::Connection,
    fabric: &fabric::Fabric,
    cm: &dyn certmanager::CertManager,
    node_id: u64,
    controller_id: u64,
) -> Result<session::Session> {
    log::debug!("auth_sigma");
    let exchange = rand::random();
    let mut session = session::Session::new();
    let mut retrctx = retransmit::RetrContext::new(connection, &mut session);
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
        return Err(anyhow::anyhow!("sigma2 not received, status: {}", sigma2.status_report_info.context("status report info missing")?.to_string()));
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

