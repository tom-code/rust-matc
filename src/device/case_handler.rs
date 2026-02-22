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
        self.active_subscriptions.clear();

        let fabric_info = self
            .fabric_info
            .as_ref()
            .context("Sigma1 received but no fabric info from commissioning")?;

        let ca_public_key = self.extract_ca_public_key()?;
        let fabric_id = self.extract_fabric_id()?;
        let ca_id = self.extract_ca_id()?;

        let mut fabric = fabric::Fabric::new(fabric_id, ca_id, &ca_public_key);
        fabric.ipk_epoch_key = fabric_info.ipk.clone();

        let sigma2_ctx = sigma::sigma2_respond(
            &fabric,
            proto_payload,
            &self.operational_key,
            &fabric_info.device_matter_cert,
            self.icac.as_deref(),
        )?;

        let sigma2_payload = sigma2_ctx.sigma2_payload.clone();
        let resp = device_messages::sigma2_msg(
            proto_header.exchange_id,
            &sigma2_payload,
            msg_header.message_counter as i64,
        )?;

        self.send_unencrypted(addr, &resp, msg_header.source_node_id.as_deref())
            .await?;

        self.case_state = Some(CaseState {
            sigma2_ctx,
            exchange_id: proto_header.exchange_id,
        });
        if let Some(ref mut fi) = self.fabric_info {
            fi.fabric = Some(fabric);
        }
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
            .case_state
            .as_ref()
            .context("Sigma3 received but no CASE state")?;
        let fabric_info = self.fabric_info.as_ref().context("No fabric info")?;

        let fabric = fabric_info.fabric.as_ref().context("Fabric not set")?;
        let result = sigma::sigma3_verify(fabric, &case_state.sigma2_ctx, proto_payload)?;

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
        // Set node IDs for nonce computation
        let controller_id = fabric_info.controller_id;
        let mut remote_node = Vec::new();
        remote_node.write_u64::<LittleEndian>(controller_id)?;
        ses.remote_node = Some(remote_node);

        let device_node_id = self.extract_device_node_id()?;
        let mut local_node = Vec::new();
        local_node.write_u64::<LittleEndian>(device_node_id)?;
        ses.local_node = Some(local_node);

        self.case_session = Some(ses);

        log::info!(
            "CASE: Session established (my_session={}, remote_session={})",
            case_state.sigma2_ctx.responder_session_id,
            case_state.sigma2_ctx.initiator_session_id,
        );
        Ok(())
    }
}
