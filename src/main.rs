
use byteorder::{LittleEndian, WriteBytesExt};

use anyhow::{Context, Result};


use messages::ProtocolMessageHeader;
use rand::RngCore;
use session::Session;
use transport::Transport;

mod messages;
mod tlv;
mod transport;
mod spake2p;
mod cert;
mod asn1;
mod mattercert;
mod fabric;
mod cryptoutil;
mod session;
mod sigma;
mod certmanager;


fn get_next_message(transport: &transport::Transport, session: &mut Session) -> Result<messages::Message> {
    loop {
        let resp = transport.receive()?;
        let resp = session.decode_message(&resp)?;
        let decoded = messages::Message::decode(&resp)?;
        if decoded.protocol_header.protocol_id == messages::ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL
            && decoded.protocol_header.opcode == messages::ProtocolMessageHeader::OPCODE_ACK {
                continue
        }
        let ack = messages::ack(decoded.protocol_header.exchange_id, decoded.message_header.message_counter as i64)?;
        let out = session.encode_message(&ack)?;
        transport.send(&out);
        return Ok(decoded)
    }

}


fn pin_to_passcode(pin: u32) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.write_u32::<LittleEndian>(pin)?;
    Ok(out)
}

fn spake_flow(transport: &Transport, session: &mut Session, pin: u32) -> Result<()> {

    // send pbkdf
    let pbkdf_req_protocol_message = messages::pbkdf_req(1)?;
    let pbkdf_req = session.encode_message(&pbkdf_req_protocol_message)?;
    transport.send(&pbkdf_req);

    // get pbkdf response
    let pbkdf_response = get_next_message(transport, session)?;
    if pbkdf_response.protocol_header.protocol_id != ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL
        || pbkdf_response.protocol_header.opcode != ProtocolMessageHeader::OPCODE_PBKDF_RESP {
            return Err(anyhow::anyhow!("pbkdf response not received"))
        }

    let iterations = pbkdf_response.tlv.get_int(&[4, 1]).context("pbkdf_response - iterations missing")?;
    let salt = pbkdf_response.tlv.get_octet_string(&[4, 2]).context("pbkdf_response - salt missing")?;
    let p_session = pbkdf_response.tlv.get_int(&[3]).context("pbkdf_response - session missing")?;

    // send pake1
    let engine = spake2p::Engine::new()?;
    let mut ctx = engine.start(&pin_to_passcode(pin)?, salt, iterations as u32)?;
    let pake1_protocol_message = messages::pake1(1, ctx.x.as_bytes(), -1)?;
    let pake1 = session.encode_message(&pake1_protocol_message)?;
    transport.send(&pake1);


    // receive pake2
    let pake2 = get_next_message(transport, session)?;
    if pake2.protocol_header.protocol_id != ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL
        || pake2.protocol_header.opcode != ProtocolMessageHeader::OPCODE_PBKDF_PAKE2 {
            return Err(anyhow::anyhow!("pake2 not received"))
        }
    let pake2_pb = pake2.tlv.get_octet_string(&[1]).context("pake2 pb tlv missing")?;
    ctx.y = p256::EncodedPoint::from_bytes(pake2_pb)?;

    // send pake3
    let mut hash_seed = "CHIP PAKE V1 Commissioning".as_bytes().to_vec();
    hash_seed.extend_from_slice(&pbkdf_req_protocol_message[6..]);
    hash_seed.extend_from_slice(&pbkdf_response.payload);
    engine.finish(&mut ctx, &hash_seed)?;
    let pake3_protocol_message = messages::pake3(1, &ctx.ca, -1)?;
    let pake3 = session.encode_message(&pake3_protocol_message)?;
    transport.send(&pake3);


    let pake3_resp = get_next_message(transport, session)?;
    println!("pake3_resp {:?}", pake3_resp);

    // some leftover ack
    let unk = transport.receive()?;
    let unk2 = messages::Message::decode(&unk);
    println!("?????some{:?}", unk2);

    session.encrypt_key = ctx.encrypt_key;
    session.decrypt_key = ctx.decrypt_key;
    session.session_id = p_session as u16;
    Ok(())
}


fn comission(transport: &Transport, session: &mut Session, fabric: &fabric::Fabric, cm: &dyn certmanager::CertManager, node_id: u64, controller_id: u64) -> Result<()> {

    // node operational credentials procedure

    // step 1 send csr request
    let mut tlv = tlv::TlvBuffer::new();
    let mut random_csr_nonce = vec![0; 32];
    rand::thread_rng().fill_bytes(&mut random_csr_nonce);
    tlv.write_octetstring(0, &random_csr_nonce)?;
    let csr_request = messages::im_invoke_request(0, 0x3e, 4, 1, &tlv.data, false)?;
    let csr_request = session.encode_message(&csr_request)?;
    transport.send(&csr_request);


    // step 2 receive csr request response
    let csr_msg = get_next_message(transport, session)?;

    let csr_tlve = csr_msg.tlv.get_octet_string(&[1, 0, 0, 1, 0]).context("csr tlv missing")?;
    let csr_t = tlv::decode_tlv(csr_tlve).context("csr tlv can't decode")?;
    let csr = csr_t.get_octet_string(&[1]).context("csr tlv in tlv missing")?;
    let csrd = x509_cert::request::CertReq::try_from(csr)?;


    // step 3 push ca cert
    let ca_pubkey = cm.get_ca_key()?.public_key().to_sec1_bytes();
    let ca_cert = cm.get_ca_cert()?;
    let mcert = mattercert::convert_x509_bytes_to_matter(&ca_cert, &ca_pubkey)?;
    let mut tlv = tlv::TlvBuffer::new();
    tlv.write_octetstring(0, &mcert)?;
    let t1 = messages::im_invoke_request(0, 0x3e, 0xb, 1, &tlv.data, false)?;
    let out = session.encode_message(&t1)?;
    transport.send(&out);

    
    // push ca cert response
    println!("a1 {:?}", get_next_message(transport, session));


    // step 4 push device cert
    let ca_id = fabric.ca_id;
    let node_public_key = csrd.info.public_key.subject_public_key.as_bytes().context("can't extract pubkey from csr")?;
    let ca_private = cm.get_ca_key()?;
    let noc_x509 = cert::encode_x509(node_public_key, node_id, fabric.id, ca_id, &ca_private, false)?;
    let noc = mattercert::convert_x509_bytes_to_matter(&noc_x509, &ca_pubkey)?;
    let mut tlv = tlv::TlvBuffer::new();
    tlv.write_octetstring(0, &noc)?;
    tlv.write_octetstring(2, &fabric.ipk_epoch_key)?;
    tlv.write_uint64(3, fabric.id)?;
    tlv.write_uint64(4, controller_id)?;
    let t1 = messages::im_invoke_request(0, 0x3e, 0x6, 1, &tlv.data, false)?;
    let out = session.encode_message(&t1)?;
    transport.send(&out);

    println!("x1 {:?}", get_next_message(transport, session));
    println!("x1 {:?}", transport.receive()?); // ack
    Ok(())
}



fn sigma(transport: &Transport, session: &mut Session, fabric: &fabric::Fabric, cm: &dyn certmanager::CertManager, node_id: u64, controller_id: u64) -> Result<session::Session> {

    let mut ctx = sigma::SigmaContext::new(node_id);
    let ca_pubkey = cm.get_ca_key()?.public_key().to_sec1_bytes();
    sigma::sigma1(fabric, &mut ctx, &ca_pubkey)?;
    let s1 = messages::sigma1(11, &ctx.sigma1_payload)?;
    let out = session.encode_message(&s1)?;
    transport.send(&out);

    // receive sigma2
    let sigma2 = get_next_message(transport, session)?;
    ctx.sigma2_payload = sigma2.payload;
    ctx.responder_session = sigma2.tlv.get_int(&[2]).context("responder session tlv missing in sigma2")? as u16;
    ctx.responder_public = sigma2.tlv.get_octet_string(&[3]).context("responder public tlv missing in sigma2")?.to_vec();

    let controller_private = cm.get_user_key(controller_id)?;
    let controller_x509 = cm.get_user_cert(controller_id)?;
    let controller_matter_cert = mattercert::convert_x509_bytes_to_matter(&controller_x509, &ca_pubkey)?;


    // send sigma3
    sigma::sigma3(fabric, &mut ctx, &controller_private.to_sec1_der()?, &controller_matter_cert)?;
    let sigma3 = messages::sigma3(11, &ctx.sigma3_payload)?;
    let out = session.encode_message(&sigma3)?;
    transport.send(&out);

    let status = get_next_message(transport, session)?;
    println!("sigma status {:?}", status);

    //session keys
    let mut th = ctx.sigma1_payload.clone();
    th.extend_from_slice(&ctx.sigma2_payload);

    let mut transcript = th;
    transcript.extend_from_slice(&ctx.sigma3_payload);
    let transcript_hash = cryptoutil::sha256(&transcript);
    let mut salt = fabric.signed_ipk()?;
    salt.extend_from_slice(&transcript_hash);
    let shared = ctx.shared.context("shared secret not in context")?;
    let keypack = cryptoutil::hkdf_sha256(&salt, shared.raw_secret_bytes().as_slice(), "SessionKeys".as_bytes(), 16*3)?;
    let mut ses = Session::new();
    ses.session_id = ctx.responder_session;
    ses.decrypt_key = keypack[16..32].to_vec();
    ses.encrypt_key = keypack[..16].to_vec();
    ses.local_node = Vec::new();
    ses.local_node.write_u64::<LittleEndian>(controller_id)?;
    ses.remote_node = Vec::new();
    ses.remote_node.write_u64::<LittleEndian>(node_id)?;
    ses.counter = 100;

    Ok(ses)
}



fn main() {
    let mut session = Session::new();
    let transport = transport::Transport::new("192.168.5.77:5540");

    let fabric = fabric::Fabric::new(0x110);
    let cm: Box<dyn certmanager::CertManager> = Box::new(certmanager::FileCertManager::new(0x110));

 
    spake_flow(&transport, &mut session, 123456).unwrap();
    comission(&transport, &mut session, &fabric, cm.as_ref(), 600, 100).unwrap();

    let mut session = Session::new();
    session.counter = 100;
    let mut ses2 = sigma(&transport, &mut session, &fabric, cm.as_ref(), 600, 100).unwrap();

    println!("x1 {:?}", transport.receive().unwrap()); // ack

    let testm = messages::im_read_request(0, 0x1d, 0).unwrap();
    let out = ses2.encode_message(&testm).unwrap();
    transport.send(&out);

    let status = get_next_message(&transport, &mut ses2).unwrap();
    println!("res {:?}", status);
}

