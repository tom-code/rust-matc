use anyhow::{Context, Ok, Result};
use byteorder::{LittleEndian, WriteBytesExt};

use crate::{device_messages, fabric, messages, session, sigma};

use super::Device;
use super::types::CaseState;

impl Device {
    pub(crate) async fn handle_sigma1(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        proto_payload: &[u8],
    ) -> Result<()> {
        log::info!("CASE: Received Sigma1");

        // Check for session resumption request (tags 5=resumptionID, 6=initiatorResumeMIC)
        if let std::result::Result::Ok(sigma1_tlv) = crate::tlv::decode_tlv(proto_payload) {
            if sigma1_tlv.get_octet_string(&[6]).is_some() {
                log::info!("CASE Sigma1: initiator requesting session resumption (not supported)");
            }
        }

        // Parse Sigma1 to find the matching fabric via destination ID
        let sigma1_tlv = crate::tlv::decode_tlv(proto_payload)?;
        let initiator_random = sigma1_tlv
            .get_octet_string(&[1])
            .context("Sigma1: initiator_random missing")?;
        let received_destination_id = sigma1_tlv
            .get_octet_string(&[3])
            .context("Sigma1: destinationId missing")?;

        let fabric_idx = self
            .find_fabric_by_destination_id(initiator_random, received_destination_id)
            .context("Sigma1: no fabric matches destinationId")?;

        let fabric_index = self.fabrics[fabric_idx].fabric_index;
        let ca_public_key = self.fabrics[fabric_idx].ca_public_key()?;
        let fabric_id = self.fabrics[fabric_idx].fabric_id()?;
        let ca_id = self.fabrics[fabric_idx].ca_id()?;
        let device_node_id = self.fabrics[fabric_idx].device_node_id()?;
        let ipk = self.fabrics[fabric_idx].ipk.clone();
        let device_matter_cert = self.fabrics[fabric_idx].device_matter_cert.clone();
        let icac = self.fabrics[fabric_idx].icac.clone();

        log::info!(
            "CASE Sigma1: fabric_index={}, fabric_id={:016X}, node_id={:016X}",
            fabric_index,
            fabric_id,
            device_node_id
        );

        let fabric = fabric::Fabric::new(fabric_id, ca_id, &ca_public_key, &ipk);

        let sigma2_ctx = sigma::sigma2_respond(
            &fabric,
            proto_payload,
            &self.operational_key,
            &device_matter_cert,
            icac.as_deref(),
            &ca_public_key,
            device_node_id,
        )?;

        let sigma2_payload = sigma2_ctx.sigma2_payload.clone();
        let resp = device_messages::sigma2_msg(
            proto_header.exchange_id,
            &sigma2_payload,
            msg_header.message_counter as i64,
        )?;

        self.send_unencrypted(addr, &resp, msg_header.source_node_id.as_deref())
            .await?;

        self.case_states.insert(proto_header.exchange_id, CaseState {
            sigma2_ctx,
            exchange_id: proto_header.exchange_id,
            fabric_index,
        });
        self.fabrics[fabric_idx].fabric = Some(fabric);
        Ok(())
    }

    pub(crate) async fn handle_sigma3(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        proto_payload: &[u8],
    ) -> Result<()> {
        log::info!("CASE: Received Sigma3");

        let case_state = self
            .case_states
            .remove(&proto_header.exchange_id)
            .context("Sigma3: no CASE state for this exchange")?;

        let fabric_index = case_state.fabric_index;
        let fabric_idx = self
            .fabrics
            .iter()
            .position(|fi| fi.fabric_index == fabric_index)
            .context("Sigma3: no fabric for case_state fabric_index")?;

        let result = {
            let fabric = self.fabrics[fabric_idx]
                .fabric
                .as_ref()
                .context("Sigma3: fabric not set (Sigma1 not processed first)")?;
            sigma::sigma3_verify(fabric, &case_state.sigma2_ctx, proto_payload)?
        };

        let controller_id = self.fabrics[fabric_idx].controller_id;
        let device_node_id = self.fabrics[fabric_idx].device_node_id()?;

        // Send status OK
        let resp = device_messages::status_report(
            proto_header.exchange_id,
            0,
            0,
            0,
            msg_header.message_counter as i64,
        )?;
        self.send_unencrypted(addr, &resp, msg_header.source_node_id.as_deref())
            .await?;

        // Establish CASE session
        let mut ses = session::Session::new();
        ses.my_session_id = case_state.sigma2_ctx.responder_session_id;
        ses.session_id = case_state.sigma2_ctx.initiator_session_id;
        ses.set_encrypt_key(&result.encrypt_key);
        ses.set_decrypt_key(&result.decrypt_key);
        ses.fabric_index = fabric_index;

        let mut remote_node = Vec::new();
        remote_node.write_u64::<LittleEndian>(controller_id)?;
        ses.remote_node = Some(remote_node);

        let mut local_node = Vec::new();
        local_node.write_u64::<LittleEndian>(device_node_id)?;
        ses.local_node = Some(local_node);

        self.case_sessions.push(ses);

        log::info!(
            "CASE: Session established (my_session={}, remote_session={}, fabric_index={})",
            case_state.sigma2_ctx.responder_session_id,
            case_state.sigma2_ctx.initiator_session_id,
            fabric_index,
        );
        Ok(())
    }

    pub(crate) async fn handle_status_report(&mut self, payload: &[u8]) -> Result<()> {
        match messages::StatusReportInfo::parse(payload) {
            std::result::Result::Ok(info) => log::warn!("Received StatusReport on secure channel: {}", info),
            std::result::Result::Err(e) => log::warn!("Received StatusReport on secure channel (parse error: {})", e),
        }
        Ok(())
    }
}
