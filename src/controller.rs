use std::{sync::Arc, time::Duration};

use crate::{
    cert_matter, cert_x509, certmanager,
    fabric::{self, Fabric},
    messages::{self, Message},
    retransmit, session, sigma, spake2p,
    tlv::{self, TlvItemValue},
    transport,
    util::cryptoutil,
};
use anyhow::{Context, Result};
use byteorder::{LittleEndian, WriteBytesExt};
use rand::RngCore;

pub struct Controller {
    certmanager: Arc<dyn certmanager::CertManager>,
    transport: Arc<transport::Transport>,
    fabric: fabric::Fabric,
}

pub struct Connection {
    connection: Arc<transport::Connection>,
    session: session::Session,
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
        let session = commission(
            connection,
            &mut session,
            &self.fabric,
            self.certmanager.as_ref(),
            node_id,
            controller_id,
        )
        .await?;
        Ok(Connection {
            connection: connection.clone(),
            session,
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
            connection: connection.clone(),
            session,
        })
    }
}

/// Authenticated virtual connection can bse used to send commands to device.
impl Connection {

    /// Read attribute from device and return parsed matter protocol response.
    pub async fn read_request(
        &mut self,
        endpoint: u16,
        cluster: u32,
        attr: u32,
    ) -> Result<Message> {
        read_request(&self.connection, &mut self.session, endpoint, cluster, attr).await
    }

    /// Read attribute from device and return tlv with attribute value.
    pub async fn read_request2(
        &mut self,
        endpoint: u16,
        cluster: u32,
        attr: u32,
    ) -> Result<TlvItemValue> {
        let res =
            read_request(&self.connection, &mut self.session, endpoint, cluster, attr).await?;
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
        &mut self,
        endpoint: u16,
        cluster: u32,
        command: u32,
        payload: &[u8],
    ) -> Result<Message> {
        invoke_request(
            &self.connection,
            &mut self.session,
            endpoint,
            cluster,
            command,
            payload,
        )
        .await
    }

    /// Invoke command
    pub async fn invoke_request2(
        &mut self,
        endpoint: u16,
        cluster: u32,
        command: u32,
        payload: &[u8],
    ) -> Result<TlvItemValue> {
        let res = invoke_request(
            &self.connection,
            &mut self.session,
            endpoint,
            cluster,
            command,
            payload,
        )
        .await?;
        let o = res.tlv.get(&[1, 0, 1, 1]).context("result not found")?;
        Ok(o.clone())
    }
}

async fn get_next_message(
    connection: &transport::Connection,
    session: &mut session::Session,
) -> Result<messages::Message> {
    loop {
        let resp = connection.receive(Duration::from_secs(3)).await?;
        let resp = session.decode_message(&resp)?;
        let decoded = messages::Message::decode(&resp)?;
        if decoded.protocol_header.protocol_id
            == messages::ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL
            && decoded.protocol_header.opcode == messages::ProtocolMessageHeader::OPCODE_ACK
        {
            continue;
        }
        let ack = messages::ack(
            decoded.protocol_header.exchange_id,
            decoded.message_header.message_counter as i64,
        )?;
        let out = session.encode_message(&ack)?;
        connection.send(&out).await?;
        return Ok(decoded);
    }
}

fn pin_to_passcode(pin: u32) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.write_u32::<LittleEndian>(pin)?;
    Ok(out)
}

async fn auth_spake(connection: &transport::Connection, pin: u32) -> Result<session::Session> {
    let exchange = rand::random();
    let mut session = session::Session::new();
    let mut retrctx = retransmit::RetrContext::new(connection, &mut session);
    // send pbkdf
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
        &ctx.ca.context("ca value not poresent in context")?,
        -1,
    )?;
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
    Ok(session)
}

async fn push_ca_cert(
    retrcrx: &mut retransmit::RetrContext<'_>,
    cm: &dyn certmanager::CertManager,
) -> Result<()> {
    let ca_pubkey = cm.get_ca_key()?.public_key().to_sec1_bytes();
    let ca_cert = cm.get_ca_cert()?;
    let mcert = cert_matter::convert_x509_bytes_to_matter(&ca_cert, &ca_pubkey)?;
    let mut tlv = tlv::TlvBuffer::new();
    tlv.write_octetstring(0, &mcert)?;
    let t1 = messages::im_invoke_request(0, 0x3e, 0xb, 1, &tlv.data, false)?;
    retrcrx.send(&t1).await?;

    // push ca cert response
    let resp = retrcrx.get_next_message().await?;
    let noc_status = {
        resp.tlv
            .get_int(&[1, 0, 1, 1, 0])
            .context("can't get status for AddTrustedRootCertificate")?
    };
    if noc_status != 0 {
        return Err(anyhow::anyhow!(
            "AddTrustedRootCertificate failed with status {}",
            noc_status
        ));
    }
    Ok(())
}

async fn push_device_cert(
    retrcrx: &mut retransmit::RetrContext<'_>,
    cm: &dyn certmanager::CertManager,
    csrd: x509_cert::request::CertReq,
    node_id: u64,
    controller_id: u64,
    fabric: &Fabric,
) -> Result<()> {
    let ca_id = fabric.ca_id;
    let ca_pubkey = cm.get_ca_key()?.public_key().to_sec1_bytes();
    let node_public_key = csrd
        .info
        .public_key
        .subject_public_key
        .as_bytes()
        .context("can't extract pubkey from csr")?;
    let ca_private = cm.get_ca_key()?;
    let noc_x509 = cert_x509::encode_x509(
        node_public_key,
        node_id,
        cm.get_fabric_id(),
        ca_id,
        &ca_private,
        false,
    )?;
    let noc = cert_matter::convert_x509_bytes_to_matter(&noc_x509, &ca_pubkey)?;
    let mut tlv = tlv::TlvBuffer::new();
    tlv.write_octetstring(0, &noc)?;
    tlv.write_octetstring(2, &fabric.ipk_epoch_key)?;
    tlv.write_uint64(3, controller_id)?;
    tlv.write_uint64(4, 101)?;
    let t1 = messages::im_invoke_request(0, 0x3e, 0x6, 1, &tlv.data, false)?;
    retrcrx.send(&t1).await?;

    let resp = retrcrx.get_next_message().await?;
    let noc_status = {
        resp.tlv
            .get_int(&[1, 0, 0, 1, 0])
            .context("can't get status for AddNOC")?
    };
    if noc_status != 0 {
        return Err(anyhow::anyhow!("AddNOC failed with status {}", noc_status));
    }
    Ok(())
}

async fn send_csr(
    retrcrx: &mut retransmit::RetrContext<'_>,
) -> Result<x509_cert::request::CertReq> {
    let mut tlv = tlv::TlvBuffer::new();
    let mut random_csr_nonce = vec![0; 32];
    rand::thread_rng().fill_bytes(&mut random_csr_nonce);
    tlv.write_octetstring(0, &random_csr_nonce)?;
    let csr_request = messages::im_invoke_request(0, 0x3e, 4, 1, &tlv.data, false)?;
    retrcrx.send(&csr_request).await?;

    let csr_msg = retrcrx.get_next_message().await?;

    let csr_tlve = csr_msg
        .tlv
        .get_octet_string(&[1, 0, 0, 1, 0])
        .context("csr tlv missing")?;
    let csr_t = tlv::decode_tlv(csr_tlve).context("csr tlv can't decode")?;
    let csr = csr_t
        .get_octet_string(&[1])
        .context("csr tlv in tlv missing")?;
    let csrd = x509_cert::request::CertReq::try_from(csr)?;
    Ok(csrd)
}

async fn commissioning_complete(
    connection: &transport::Connection,
    cm: &dyn certmanager::CertManager,
    node_id: u64,
    controller_id: u64,
    fabric: &Fabric,
) -> Result<session::Session> {
    let mut ses = auth_sigma(connection, fabric, cm, node_id, controller_id).await?;
    let t1 = messages::im_invoke_request(0, 0x30, 0x4, 30, &[], false)?;
    let out = ses.encode_message(&t1)?;
    connection.send(&out).await?;
    let resp = get_next_message(connection, &mut ses).await?;
    let comresp_status = {
        resp.tlv
            .get_int(&[1, 0, 0, 1, 0])
            .context("can't get status from CommissioningCompleteResponse")?
    };
    if comresp_status != 0 {
        return Err(anyhow::anyhow!(
            "CommissioningComplete failed with status {}",
            comresp_status
        ));
    }
    Ok(ses)
}

async fn commission(
    connection: &transport::Connection,
    session: &mut session::Session,
    fabric: &fabric::Fabric,
    cm: &dyn certmanager::CertManager,
    node_id: u64,
    controller_id: u64,
) -> Result<session::Session> {
    // node operational credentials procedure
    let mut retrctx = retransmit::RetrContext::new(connection, session);

    let csrd = send_csr(&mut retrctx).await?;

    push_ca_cert(&mut retrctx, cm).await?;

    push_device_cert(&mut retrctx, cm, csrd, node_id, controller_id, fabric).await?;

    let ses = commissioning_complete(connection, cm, node_id, controller_id, fabric).await?;

    Ok(ses)
}

async fn auth_sigma(
    connection: &transport::Connection,
    fabric: &fabric::Fabric,
    cm: &dyn certmanager::CertManager,
    node_id: u64,
    controller_id: u64,
) -> Result<session::Session> {
    let exchange = rand::random();
    let mut session = session::Session::new();
    let mut retrctx = retransmit::RetrContext::new(connection, &mut session);
    retrctx.subscribe_exchange(exchange);
    let mut ctx = sigma::SigmaContext::new(node_id);
    let ca_pubkey = cm.get_ca_key()?.public_key().to_sec1_bytes();
    sigma::sigma1(fabric, &mut ctx, &ca_pubkey)?;
    let s1 = messages::sigma1(exchange, &ctx.sigma1_payload)?;

    retrctx.send(&s1).await?;

    // receive sigma2
    let sigma2 = retrctx.get_next_message().await?;
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
    sigma::sigma3(
        fabric,
        &mut ctx,
        &controller_private.to_sec1_der()?,
        &controller_matter_cert,
    )?;
    let sigma3 = messages::sigma3(exchange, &ctx.sigma3_payload)?;
    retrctx.send(&sigma3).await?;

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

async fn read_request(
    connection: &transport::Connection,
    session: &mut session::Session,
    endpoint: u16,
    cluster: u32,
    attr: u32,
) -> Result<Message> {
    let testm = messages::im_read_request(endpoint, cluster, attr)?;
    let out = session.encode_message(&testm)?;
    connection.send(&out).await?;

    let result = get_next_message(connection, session).await?;
    Ok(result)
}

async fn invoke_request(
    connection: &transport::Connection,
    session: &mut session::Session,
    endpoint: u16,
    cluster: u32,
    command: u32,
    payload: &[u8],
) -> Result<Message> {
    let exchange = rand::random();
    let testm = messages::im_invoke_request(endpoint, cluster, command, exchange, payload, false)?;
    let out = session.encode_message(&testm)?;
    connection.send(&out).await?;

    let result = get_next_message(connection, session).await?;
    Ok(result)
}
