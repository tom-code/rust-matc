use std::sync::Arc;

use crate::{
    cert_matter, cert_x509, certmanager, fabric,
    messages::{self, Message},
    session, sigma, spake2p, tlv, transport,
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
trait IsSync: Sync {}
impl IsSync for Controller {}

impl Controller {
    pub fn new(
        certmanager: &Arc<dyn certmanager::CertManager>,
        transport: &Arc<transport::Transport>,
        fabric_id: u64,
    ) -> Arc<Self> {
        let fabric = fabric::Fabric::new(fabric_id, 1, &certmanager.get_ca_public_key().unwrap());
        Arc::new(Self {
            certmanager: certmanager.clone(),
            transport: transport.clone(),
            fabric,
        })
    }
    pub async fn commission(
        &self,
        connection: &Arc<transport::Connection>,
        pin: u32,
        node_id: u64,
        controller_id: u64,
    ) -> Result<()> {
        let mut session = auth_spake(connection, pin).await?;
        comission(
            connection,
            &mut session,
            &self.fabric,
            self.certmanager.as_ref(),
            node_id,
            controller_id,
        )
        .await
    }
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

impl Connection {
    pub async fn read_request(
        &mut self,
        endpoint: u16,
        cluster: u32,
        attr: u32,
    ) -> Result<Message> {
        read_request(&self.connection, &mut self.session, endpoint, cluster, attr).await
    }
    pub async fn invoke_request(
        &mut self,
        endpoint: u16,
        cluster: u32,
        command: u32,
    ) -> Result<Message> {
        invoke_request(
            &self.connection,
            &mut self.session,
            endpoint,
            cluster,
            command,
            &[],
        )
        .await
    }
}

async fn get_next_message(
    connection: &transport::Connection,
    session: &mut session::Session,
) -> Result<messages::Message> {
    loop {
        let resp = connection.receive().await?;
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
    let mut session = session::Session::new();
    // send pbkdf
    let pbkdf_req_protocol_message = messages::pbkdf_req(1)?;
    let pbkdf_req = session.encode_message(&pbkdf_req_protocol_message)?;
    connection.send(&pbkdf_req).await?;

    // get pbkdf response
    let pbkdf_response = get_next_message(connection, &mut session).await?;
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
    let pake1_protocol_message = messages::pake1(1, ctx.x.as_bytes(), -1)?;
    let pake1 = session.encode_message(&pake1_protocol_message)?;
    connection.send(&pake1).await?;

    // receive pake2
    let pake2 = get_next_message(connection, &mut session).await?;
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
    let pake3_protocol_message = messages::pake3(1, &ctx.ca, -1)?;
    let pake3 = session.encode_message(&pake3_protocol_message)?;
    connection.send(&pake3).await?;

    let pake3_resp = get_next_message(connection, &mut session).await?;
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

    // some leftover ack - we must get it out before we enable encryption from this endpoint
    if connection.receive().await.is_err() {
        println!("we did not get leftover ack. we assume it will not come");
        //let _unk2 = messages::Message::decode(&unk);
    };

    session.set_encrypt_key(&ctx.encrypt_key);
    session.set_decrypt_key(&ctx.decrypt_key);
    session.session_id = p_session as u16;
    Ok(session)
}

async fn comission(
    connection: &transport::Connection,
    session: &mut session::Session,
    fabric: &fabric::Fabric,
    cm: &dyn certmanager::CertManager,
    node_id: u64,
    controller_id: u64,
) -> Result<()> {
    // node operational credentials procedure

    // step 1 send csr request
    let mut tlv = tlv::TlvBuffer::new();
    let mut random_csr_nonce = vec![0; 32];
    rand::thread_rng().fill_bytes(&mut random_csr_nonce);
    tlv.write_octetstring(0, &random_csr_nonce)?;
    let csr_request = messages::im_invoke_request(0, 0x3e, 4, 1, &tlv.data, false)?;
    let csr_request = session.encode_message(&csr_request)?;
    connection.send(&csr_request).await?;

    // step 2 receive csr request response
    let csr_msg = get_next_message(connection, session).await?;

    let csr_tlve = csr_msg
        .tlv
        .get_octet_string(&[1, 0, 0, 1, 0])
        .context("csr tlv missing")?;
    let csr_t = tlv::decode_tlv(csr_tlve).context("csr tlv can't decode")?;
    let csr = csr_t
        .get_octet_string(&[1])
        .context("csr tlv in tlv missing")?;
    let csrd = x509_cert::request::CertReq::try_from(csr)?;

    // step 3 push ca cert
    let ca_pubkey = cm.get_ca_key()?.public_key().to_sec1_bytes();
    let ca_cert = cm.get_ca_cert()?;
    let mcert = cert_matter::convert_x509_bytes_to_matter(&ca_cert, &ca_pubkey)?;
    let mut tlv = tlv::TlvBuffer::new();
    tlv.write_octetstring(0, &mcert)?;
    let t1 = messages::im_invoke_request(0, 0x3e, 0xb, 1, &tlv.data, false)?;
    let out = session.encode_message(&t1)?;
    connection.send(&out).await?;

    // push ca cert response
    //println!("a1 {:?}", get_next_message(connection, session));
    get_next_message(connection, session).await?;

    // step 4 push device cert
    let ca_id = fabric.ca_id;
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
        fabric.id,
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
    let out = session.encode_message(&t1)?;
    connection.send(&out).await?;

    get_next_message(connection, session).await?;
    connection.receive().await?;

    // send commissioning complete
    let mut ses = auth_sigma(connection, fabric, cm, node_id, controller_id).await?;
    let t1 = messages::im_invoke_request(0, 0x30, 0x4, 30, &[], false)?;
    //let t1 = messages::im_read_request(0, 0x1d, 0)?;
    let out = ses.encode_message(&t1)?;
    connection.send(&out).await?;
    get_next_message(connection, &mut ses).await?;
    connection.receive().await?;
    Ok(())
}

async fn auth_sigma(
    connection: &transport::Connection,
    fabric: &fabric::Fabric,
    cm: &dyn certmanager::CertManager,
    node_id: u64,
    controller_id: u64,
) -> Result<session::Session> {
    let mut session = session::Session::new();
    session.counter = rand::random();
    let mut ctx = sigma::SigmaContext::new(node_id);
    let ca_pubkey = cm.get_ca_key()?.public_key().to_sec1_bytes();
    sigma::sigma1(fabric, &mut ctx, &ca_pubkey)?;
    let s1 = messages::sigma1(11, &ctx.sigma1_payload)?;
    let out = session.encode_message(&s1)?;
    connection.send(&out).await?;

    // receive sigma2
    let sigma2 = get_next_message(connection, &mut session).await?;
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
    let sigma3 = messages::sigma3(11, &ctx.sigma3_payload)?;
    let out = session.encode_message(&sigma3)?;
    connection.send(&out).await?;

    let _status = get_next_message(connection, &mut session).await?;
    //println!("sigma status {:?}", status);

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

    ses.counter = rand::random();

    if connection.receive().await.is_err() {
        println!("expected ack not received");
    }

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
