use anyhow::{Context, Ok, Result};

use crate::{controller, device_messages, messages, session, spake2p, tlv};

use super::Device;
use super::types::PaseState;

impl Device {
    pub(crate) async fn handle_pbkdf_req(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        _proto_payload: &[u8],
        full_protocol_data: &[u8],
    ) -> Result<()> {
        let engine = spake2p::Engine::new()?;
        let passcode = controller::pin_to_passcode(self.config.pin)?;
        let verifier =
            spake2p::Verifier::start(&passcode, &self.salt, self.pbkdf_iterations, &engine)?;

        let pbkdf_req_hdr_size =
            if (proto_header.exchange_flags & messages::ProtocolMessageHeader::FLAG_ACK) != 0 {
                10
            } else {
                6
            };
        let pbkdf_req_tlv_data = &full_protocol_data[pbkdf_req_hdr_size..];
        let pbkdf_req_tlv = tlv::decode_tlv(pbkdf_req_tlv_data)?;
        let initator_random = pbkdf_req_tlv
            .get_octet_string(&[1])
            .context("PBKDF req: initiator random (tag 1) missing")?;
        let initiator_session_id = pbkdf_req_tlv
            .get_int(&[2])
            .context("PBKDF req: initiator session ID (tag 2) missing")?
            as u16;

        let responder_session_id: u16 = rand::random();

        let resp = device_messages::pbkdf_resp(
            proto_header.exchange_id,
            responder_session_id,
            &self.salt,
            self.pbkdf_iterations,
            msg_header.message_counter as i64,
            initator_random,
        )?;

        self.send_unencrypted(addr, &resp, msg_header.source_node_id.as_deref())
            .await?;

        let pbkdf_req_tlv_payload = pbkdf_req_tlv_data.to_vec();

        let resp_flags = resp[0];
        let resp_hdr_size = if (resp_flags & messages::ProtocolMessageHeader::FLAG_ACK) != 0 {
            10
        } else {
            6
        };
        let pbkdf_resp_tlv_payload = resp[resp_hdr_size..].to_vec();

        self.pase_state = Some(PaseState {
            engine,
            verifier,
            exchange_id: proto_header.exchange_id,
            pbkdf_req_payload: pbkdf_req_tlv_payload,
            pbkdf_resp_payload: pbkdf_resp_tlv_payload,
            responder_session_id,
            initiator_session_id,
        });

        log::info!("PASE: Sent PBKDF response");
        Ok(())
    }

    pub(crate) async fn handle_pake1(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        proto_payload: &[u8],
    ) -> Result<()> {
        log::info!("PASE: Received PAKE1");
        let state = self
            .pase_state
            .as_mut()
            .context("PAKE1 received but no PASE state")?;

        let pake1_tlv = tlv::decode_tlv(proto_payload)?;
        let x_bytes = pake1_tlv
            .get_octet_string(&[1])
            .context("PAKE1: X point missing")?;
        state.verifier.x = p256::EncodedPoint::from_bytes(x_bytes)?;

        // Compute hash seed
        let mut hash_seed = "CHIP PAKE V1 Commissioning".as_bytes().to_vec();
        hash_seed.extend_from_slice(&state.pbkdf_req_payload);
        hash_seed.extend_from_slice(&state.pbkdf_resp_payload);

        state.verifier.finish(&hash_seed, &state.engine)?;

        let cb = state
            .verifier
            .cb
            .as_ref()
            .context("cb not computed")?
            .clone();
        let y_bytes = state.verifier.y.as_bytes().to_vec();

        let resp = device_messages::pake2(
            proto_header.exchange_id,
            &y_bytes,
            &cb,
            msg_header.message_counter as i64,
        )?;
        self.send_unencrypted(addr, &resp, msg_header.source_node_id.as_deref())
            .await?;

        log::info!("PASE: Sent PAKE2");
        Ok(())
    }

    pub(crate) async fn handle_pake3(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        proto_payload: &[u8],
    ) -> Result<()> {
        log::info!("PASE: Received PAKE3");
        let state = self
            .pase_state
            .as_ref()
            .context("PAKE3 received but no PASE state")?;

        let pake3_tlv = tlv::decode_tlv(proto_payload)?;
        let ca_received = pake3_tlv
            .get_octet_string(&[1])
            .context("PAKE3: cA missing")?;

        state.verifier.verify_ca(ca_received)?;

        let resp = device_messages::status_report(
            proto_header.exchange_id,
            0, // Success
            0, // PROTOCOL_ID_SECURE_CHANNEL
            0, // SessionEstablishmentSuccess
            msg_header.message_counter as i64,
        )?;
        self.send_unencrypted(addr, &resp, msg_header.source_node_id.as_deref())
            .await?;

        // Establish PASE session
        let mut ses = session::Session::new();
        ses.my_session_id = state.responder_session_id;
        ses.session_id = state.initiator_session_id;

        ses.set_decrypt_key(
            state
                .verifier
                .decrypt_key
                .as_ref()
                .context("decrypt key missing")?,
        );
        ses.set_encrypt_key(
            state
                .verifier
                .encrypt_key
                .as_ref()
                .context("encrypt key missing")?,
        );
        self.pase_session = Some(ses);

        log::info!(
            "PASE: Session established (my_session={}, remote_session={})",
            state.responder_session_id,
            state.initiator_session_id
        );
        Ok(())
    }
}
