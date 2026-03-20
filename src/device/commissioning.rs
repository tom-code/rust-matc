use anyhow::{Context, Ok, Result};

use crate::device::crypto::TEST_CERTIFICATION_DECLARATION;
use crate::{clusters, device_messages, messages, tlv};

use super::Device;
use super::types::FabricInfo;

impl Device {
    pub(crate) async fn handle_csr_request(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        invoke_tlv: &tlv::TlvItem,
    ) -> Result<()> {
        log::info!("IM: CSR Request");

        // Extract the CSR nonce from the controller's request (tag 0 in command fields)
        let csr_nonce = invoke_tlv
            .get_octet_string(&[2, 0, 1, 0])
            .context("CSR Request: nonce (tag 0) missing")?;

        let csr_der = self.generate_csr()?;

        let mut nocsr_tlv = tlv::TlvBuffer::new();
        nocsr_tlv.write_anon_struct()?;
        nocsr_tlv.write_octetstring(1, &csr_der)?;
        nocsr_tlv.write_octetstring(2, csr_nonce)?;
        nocsr_tlv.write_struct_end()?;

        let mut tlv_buf = tlv::TlvBuffer::new();
        tlv_buf.write_octetstring(0, &nocsr_tlv.data)?;
        let dac_key = self.load_dac_signing_key()?;
        let mut data_to_sign_nocsr_tbs = nocsr_tlv.data.clone();
        data_to_sign_nocsr_tbs.extend_from_slice(
            self.pase_state
                .as_ref()
                .unwrap()
                .verifier
                .attestation_challenge
                .as_ref()
                .unwrap(),
        );

        let sig = dac_key.sign_recoverable(&data_to_sign_nocsr_tbs)?.0;

        tlv_buf.write_octetstring(1, &sig.to_bytes())?;

        let resp = device_messages::im_invoke_response_data(
            proto_header.exchange_id,
            0, // endpoint
            0x3E,
            0x05, // CSRResponse
            &tlv_buf.data,
            msg_header.message_counter as i64,
        )?;

        self.send_reply_by_session(addr, msg_header.session_id, &resp)
            .await
    }

    fn generate_csr(&self) -> Result<Vec<u8>> {
        let public_key = self.operational_key.public_key();
        let public_key_bytes = public_key.to_sec1_bytes();

        let signing_key: ecdsa::SigningKey<p256::NistP256> =
            ecdsa::SigningKey::from(&self.operational_key);

        use crate::util::asn1::Encoder;
        let mut enc = Encoder::new();

        // CertificationRequestInfo SEQUENCE
        enc.start_seq(0x30)?;

        // version INTEGER 0
        enc.write_int(0)?;

        // subject:
        enc.start_seq(0x30)?;
        enc.start_seq(0x31)?; // SET
        enc.start_seq(0x30)?; // SEQUENCE
        enc.write_oid("2.5.4.10")?;
        enc.write_string("CSR")?;
        enc.end_seq();
        enc.end_seq();
        enc.end_seq();

        // subjectPKInfo SEQUENCE
        enc.start_seq(0x30)?;
        // algorithm SEQUENCE (id-ecPublicKey + prime256v1)
        enc.start_seq(0x30)?;
        enc.write_oid("1.2.840.10045.2.1")?; // id-ecPublicKey
        enc.write_oid("1.2.840.10045.3.1.7")?; // prime256v1
        enc.end_seq();
        // subjectPublicKey BIT STRING
        let mut pk_bits: Vec<u8> = vec![0]; // 0 unused bits
        pk_bits.extend_from_slice(&public_key_bytes);
        enc.write_octet_string_with_tag(0x03, &pk_bits)?;
        enc.end_seq();

        // attributes [0]
        enc.start_seq(0xa0)?;
        enc.end_seq();

        enc.end_seq(); // end CertificationRequestInfo

        let cri_data = enc.encode();

        // Now sign the CertificationRequestInfo
        let (sig, _) = signing_key.sign_recoverable(&cri_data)?;
        let sig_bytes = sig.to_der();

        // Re-build with signature
        let mut final_enc = Encoder::new();
        final_enc.start_seq(0x30)?;

        // Write raw CRI data
        final_enc.write_raw(&cri_data);

        // signatureAlgorithm SEQUENCE
        final_enc.start_seq(0x30)?;
        final_enc.write_oid("1.2.840.10045.4.3.2")?; // ecdsa-with-SHA256
        final_enc.end_seq();

        // signature BIT STRING
        let mut sig_with_unused: Vec<u8> = vec![0]; // 0 unused bits
        sig_with_unused.extend_from_slice(sig_bytes.as_bytes());
        final_enc.write_octet_string_with_tag(0x03, &sig_with_unused)?;

        final_enc.end_seq();
        Ok(final_enc.encode())
    }

    pub(crate) async fn handle_add_trusted_root(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        invoke_tlv: &tlv::TlvItem,
    ) -> Result<()> {
        log::info!("IM: AddTrustedRootCertificate");

        let root_cert = invoke_tlv
            .get_octet_string(&[2, 0, 1, 0])
            .context("AddTrustedRoot: cert missing")?;
        self.pending_root_cert = Some(root_cert.to_vec());

        let resp = device_messages::im_invoke_response_status(
            proto_header.exchange_id,
            0,
            0x3E,
            0x0B,
            0, // success
            msg_header.message_counter as i64,
        )?;

        self.send_reply_by_session(addr, msg_header.session_id, &resp)
            .await
    }

    pub(crate) async fn handle_add_noc(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        invoke_tlv: &tlv::TlvItem,
    ) -> Result<()> {
        log::info!("IM: AddNOC");

        let noc = invoke_tlv
            .get_octet_string(&[2, 0, 1, 0])
            .context("AddNOC: noc missing")?;
        let icac = invoke_tlv.get_octet_string(&[2, 0, 1, 1]);
        let icac_opt = icac.filter(|i| !i.is_empty()).map(|i| i.to_vec());

        let ipk = invoke_tlv
            .get_octet_string(&[2, 0, 1, 2])
            .context("AddNOC: ipk missing")?;
        let controller_id = invoke_tlv
            .get_int(&[2, 0, 1, 3])
            .context("AddNOC: controller_id missing")?;
        let vendor_id = invoke_tlv.get_int(&[2, 0, 1, 4]).unwrap_or(0) as u16;

        let trusted_root_cert = self
            .pending_root_cert
            .take()
            .context("AddNOC: no trusted root cert (AddTrustedRootCertificate not called first)")?;

        let fabric_index = self.next_fabric_index;
        self.next_fabric_index += 1;

        let fabric_info = FabricInfo {
            fabric_index,
            ipk: ipk.to_vec(),
            fabric: None,
            device_matter_cert: noc.to_vec(),
            controller_id,
            vendor_id,
            trusted_root_cert,
            noc: noc.to_vec(),
            icac: icac_opt,
            label: String::new(),
        };

        let nod_id = fabric_info.device_node_id()?;
        let fabric_id = fabric_info.fabric_id()?;
        let ca_id = fabric_info.ca_id()?;
        let ca_public_key = fabric_info.ca_public_key()?;
        log::info!(
            "New fabric added: fabric_index={}, fabric_id={:016X}, ca_id={:016X}, ca_public_key={}, node_id={:016X}",
            fabric_index,
            fabric_id,
            ca_id,
            hex::encode(&ca_public_key[..8.min(ca_public_key.len())]),
            nod_id
        );

        self.fabrics.push(fabric_info);

        let new_idx = self.fabrics.len() - 1;
        self.register_operational_mdns(new_idx).await?;
        self.rebuild_fabrics_attribute()?;

        self.send_noc_response(addr, msg_header, proto_header, fabric_index)
            .await?;
        log::info!(
            "IM: AddNOC OK (controller_id={}, fabric_index={})",
            controller_id,
            fabric_index
        );
        Ok(())
    }

    pub(crate) async fn handle_update_fabric_label(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        invoke_tlv: &tlv::TlvItem,
    ) -> Result<()> {
        let label = invoke_tlv.get_string_owned(&[2, 0, 1, 0]).unwrap_or_default();
        log::info!("IM: UpdateFabricLabel label={:?}", label);

        // Identify the fabric from the session that sent this command
        let fabric_index = self
            .case_sessions
            .iter()
            .find(|s| s.my_session_id == msg_header.session_id)
            .map(|s| s.fabric_index)
            .unwrap_or(0);

        if let Some(fi) = self.fabrics.iter_mut().find(|fi| fi.fabric_index == fabric_index) {
            fi.label = label;
        }

        self.rebuild_fabrics_attribute()?;
        if let Some(ref state_dir) = self.config.state_dir.clone() {
            self.save_state(state_dir)?;
        }
        self.send_noc_response(addr, msg_header, proto_header, fabric_index)
            .await
    }

    pub(crate) async fn handle_remove_fabric(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        invoke_tlv: &tlv::TlvItem,
    ) -> Result<()> {
        let fabric_index = invoke_tlv.get_int(&[2, 0, 1, 0]).unwrap_or(0) as u8;
        log::info!("IM: RemoveFabric fabric_index={}", fabric_index);

        self.send_noc_response(addr, msg_header, proto_header, fabric_index)
            .await?;
/*
        // Send CloseSession to the requesting session if it belongs to the removed fabric
        if let Some(ses) = self
            .case_sessions
            .iter()
            .find(|s| s.my_session_id == msg_header.session_id)
        {
            log::info!(
                "IM: RemoveFabric - closing session {} that belonged to removed fabric_index {}",
                ses.my_session_id,
                fabric_index
            );
            if ses.fabric_index == fabric_index {
                log::info!("IM: RemoveFabric - sending CloseSession to session {}", ses.my_session_id);
                let exchange_id: u16 = rand::random();
                let close_data = crate::device_messages::status_report(exchange_id, 0, 0, 3, -1)?;
                let close_data = crate::device_messages::status_report_nor(exchange_id, 0, 0, 3, -1)?;
                self.send_encrypted(addr, ses, &close_data).await?;
            }
        }

        self.fabrics.retain(|fi| fi.fabric_index != fabric_index);

        // Drop CASE sessions that belonged to the removed fabric
        let removed_session_ids: std::collections::HashSet<u16> = self
            .case_sessions
            .iter()
            .filter(|s| s.fabric_index == fabric_index)
            .map(|s| s.my_session_id)
            .collect();
        self.case_sessions
            .retain(|s| s.fabric_index != fabric_index);

        // Drop subscriptions on those sessions
        let removed_sub_ids: std::collections::HashSet<u32> = self
            .active_subscriptions
            .iter()
            .filter(|s| removed_session_ids.contains(&s.session_id))
            .map(|s| s.subscription_id)
            .collect();
        self.active_subscriptions
            .retain(|s| !removed_session_ids.contains(&s.session_id));
        self.subscribe_states
            .retain(|s| !removed_sub_ids.contains(&s.subscription_id));

        self.rebuild_fabrics_attribute()?;

        if let Some(ref state_dir) = self.config.state_dir.clone() {
            self.save_state(state_dir)?;
        }
*/
        Ok(())
    }

    /// Build the Fabrics and CommissionedFabrics attributes from `self.fabrics`.
    pub(crate) fn rebuild_fabrics_attribute(&mut self) -> Result<()> {
        let mut fab_tlv = tlv::TlvBuffer::new();
        fab_tlv.write_array(2)?;
        for fi in &self.fabrics {
            let ca_public_key = fi.ca_public_key()?;
            let fabric_id = fi.fabric_id()?;
            let nod_id = fi.device_node_id()?;
            fab_tlv.write_anon_struct()?;
            fab_tlv.write_octetstring(1, &ca_public_key)?;
            fab_tlv.write_uint16(2, fi.vendor_id)?;
            fab_tlv.write_uint64(3, fabric_id)?;
            fab_tlv.write_uint64(4, nod_id)?;
            fab_tlv.write_string(5, &fi.label)?;
            fab_tlv.write_struct_end()?;
        }
        fab_tlv.write_struct_end()?;
        self.set_attribute_raw(
            0,
            clusters::defs::CLUSTER_ID_OPERATIONAL_CREDENTIALS,
            clusters::defs::CLUSTER_OPERATIONAL_CREDENTIALS_ATTR_ID_FABRICS,
            &fab_tlv.data,
        );
        self.set_attribute_u8(
            0,
            clusters::defs::CLUSTER_ID_OPERATIONAL_CREDENTIALS,
            clusters::defs::CLUSTER_OPERATIONAL_CREDENTIALS_ATTR_ID_COMMISSIONEDFABRICS,
            self.fabrics.len() as u8,
        );
        Ok(())
    }

    async fn send_noc_response(
        &self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        fabric_index: u8,
    ) -> Result<()> {
        let mut noc_resp = tlv::TlvBuffer::new();
        noc_resp.write_uint8(0, 0)?; // StatusCode = Success
        noc_resp.write_uint8(1, fabric_index)?; // FabricIndex

        let resp = device_messages::im_invoke_response_data(
            proto_header.exchange_id,
            0,
            0x3E,
            0x08, // NOCResponse command
            &noc_resp.data,
            msg_header.message_counter as i64,
        )?;

        self.send_reply_by_session(addr, msg_header.session_id, &resp)
            .await
    }

    pub(crate) async fn handle_commissioning_complete(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
    ) -> Result<()> {
        log::info!("IM: CommissioningComplete");
        self.send_general_commissioning_response(addr, msg_header, proto_header, 0x05, "")
            .await?;
        log::info!("IM: CommissioningComplete OK - device commissioned!");
        if let Some(ref state_dir) = self.config.state_dir.clone() {
            self.save_state(state_dir)?;
        }
        Ok(())
    }

    pub(crate) async fn handle_arm_failsafe(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        _invoke_tlv: &tlv::TlvItem,
    ) -> Result<()> {
        log::info!("IM: ArmFailsafe");
        self.send_general_commissioning_response(addr, msg_header, proto_header, 0x01, "ok")
            .await?;
        log::info!("IM: ArmFailsafe OK");
        Ok(())
    }

    pub(crate) async fn handle_set_regulatory_config(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
    ) -> Result<()> {
        log::info!("IM: SetRegulatoryConfig");
        self.send_general_commissioning_response(addr, msg_header, proto_header, 0x03, "")
            .await
    }

    async fn send_general_commissioning_response(
        &self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        command_id: u32,
        debug_text: &str,
    ) -> Result<()> {
        let mut resp_fields = tlv::TlvBuffer::new();
        resp_fields.write_uint8(0, 0)?; // ErrorCode = Success
        resp_fields.write_string(1, debug_text)?; // DebugText

        let resp = device_messages::im_invoke_response_data(
            proto_header.exchange_id,
            0,
            0x30,
            command_id,
            &resp_fields.data,
            msg_header.message_counter as i64,
        )?;

        self.send_commissioning_reply(addr, msg_header.session_id, &resp).await
    }

    pub(crate) async fn handle_attestation_request(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        invoke_tlv: &tlv::TlvItem,
    ) -> Result<()> {
        log::info!("IM: AttestationRequest");

        let attestation_nonce = invoke_tlv
            .get_octet_string(&[2, 0, 1, 0])
            .context("AttestationRequest: nonce (tag 0) missing")?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let mut attestation_elements = tlv::TlvBuffer::new();
        attestation_elements.write_anon_struct()?;
        attestation_elements.write_octetstring(1, TEST_CERTIFICATION_DECLARATION)?;
        attestation_elements.write_octetstring(2, attestation_nonce)?;
        attestation_elements.write_uint32(3, timestamp)?;
        attestation_elements.write_struct_end()?;

        let dac_key = self.load_dac_signing_key()?;
        let mut tbs = attestation_elements.data.clone();
        tbs.extend_from_slice(
            self.pase_state
                .as_ref()
                .unwrap()
                .verifier
                .attestation_challenge
                .as_ref()
                .unwrap(),
        );
        let sig = dac_key.sign_recoverable(&tbs)?.0;

        let mut resp_fields = tlv::TlvBuffer::new();
        resp_fields.write_octetstring(0, &attestation_elements.data)?;
        resp_fields.write_octetstring(1, &sig.to_bytes())?;

        let resp = device_messages::im_invoke_response_data(
            proto_header.exchange_id,
            0,
            0x3e,
            0x01, // AttestationResponse
            &resp_fields.data,
            msg_header.message_counter as i64,
        )?;

        self.send_commissioning_reply(addr, msg_header.session_id, &resp).await
    }

    pub(crate) async fn handle_cert_chain_request(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        in_tlv: &tlv::TlvItem,
    ) -> Result<()> {
        log::info!("IM: CertChainRequest");

        let typ = in_tlv
            .get_int(&[2, 0, 1, 0])
            .context("CertChainRequest: type (tag 0) missing")?;
        let cert_data = if typ == 1 {
            // DAC certificate chain
            crate::util::cryptoutil::read_data_from_pem(&self.config.dac_cert_path)?
        } else if typ == 2 {
            crate::util::cryptoutil::read_data_from_pem(&self.config.pai_cert_path)?
        } else {
            Vec::new()
        };

        let mut resp_fields = tlv::TlvBuffer::new();
        resp_fields.write_octetstring(0, &cert_data)?;

        let resp = device_messages::im_invoke_response_data(
            proto_header.exchange_id,
            0,
            0x3e,
            0x03, // CertChainResponse
            &resp_fields.data,
            msg_header.message_counter as i64,
        )?;

        self.send_commissioning_reply(addr, msg_header.session_id, &resp).await
    }
}
