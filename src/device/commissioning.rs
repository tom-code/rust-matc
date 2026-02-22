use anyhow::{Context, Ok, Result};

use crate::device::crypto::TEST_CERTIFICATION_DECLARATION;
use crate::{clusters, device_messages, fabric, messages, tlv};

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

        self.send_pase_encrypted(addr, &resp).await?;
        Ok(())
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
        self.trusted_root_cert = Some(root_cert.to_vec());

        let resp = device_messages::im_invoke_response_status(
            proto_header.exchange_id,
            0,
            0x3E,
            0x0B,
            0, // success
            msg_header.message_counter as i64,
        )?;

        self.send_pase_encrypted(addr, &resp).await?;
        Ok(())
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
        if let Some(icac) = icac {
            if !icac.is_empty() {
                log::info!("ICAC: {}", hex::encode(icac));
                self.icac = icac.to_vec().into();
            }
        }

        let ipk = invoke_tlv
            .get_octet_string(&[2, 0, 1, 2])
            .context("AddNOC: ipk missing")?;
        let controller_id = invoke_tlv
            .get_int(&[2, 0, 1, 3])
            .context("AddNOC: controller_id missing")?;
        let vendor_id = invoke_tlv.get_int(&[2, 0, 1, 4]).unwrap_or(0) as u16;

        self.noc = Some(noc.to_vec());

        self.fabric_info = Some(FabricInfo {
            ipk: ipk.to_vec(),
            fabric: None,
            device_matter_cert: noc.to_vec(),
            controller_id,
            vendor_id,
        });
        let nod_id = self.extract_device_node_id()?;
        {
            let ca_public_key = self.extract_ca_public_key()?;
            let fabric_id = self.extract_fabric_id()?;
            let ca_id = self.extract_ca_id()?;

            let fabric = fabric::Fabric::new(fabric_id, ca_id, &ca_public_key);

            let iname = format!(
                "{}-{:016X}",
                hex::encode_upper(fabric.compressed()?),
                nod_id
            );
            let op_port: u16 = self
                .config
                .listen_address
                .rsplit(':')
                .next()
                .and_then(|p| p.parse().ok())
                .unwrap_or(5540);
            let svc = crate::mdns2::ServiceRegistration {
                instance_name: iname,
                service_type: "_matter._tcp.local".to_string(),
                port: op_port,
                txt_records: vec![],
                hostname: self.config.hostname.clone(),
                ttl: 120,
                subtypes: vec![],
            };
            self.mdns.register_service(svc).await;

            // Build real fabric list with commissioning data
            let mut fab_tlv = tlv::TlvBuffer::new();
            fab_tlv.write_array(2)?;
            fab_tlv.write_anon_struct()?;
            fab_tlv.write_octetstring(1, &ca_public_key)?;
            fab_tlv.write_uint16(2, vendor_id)?;
            fab_tlv.write_uint64(3, fabric_id)?;
            fab_tlv.write_uint64(4, nod_id)?;
            fab_tlv.write_string(5, "")?;
            fab_tlv.write_struct_end()?;
            fab_tlv.write_struct_end()?;
            self.set_attribute_raw(
                0,
                clusters::defs::CLUSTER_ID_OPERATIONAL_CREDENTIALS,
                clusters::defs::CLUSTER_OPERATIONAL_CREDENTIALS_ATTR_ID_FABRICS,
                &fab_tlv.data,
            );
        }

        self.send_noc_response(addr, msg_header, proto_header)
            .await?;
        log::info!("IM: AddNOC OK (controller_id={})", controller_id);
        Ok(())
    }

    pub(crate) async fn handle_remove_fabric(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        _invoke_tlv: &tlv::TlvItem,
    ) -> Result<()> {
        log::info!("IM: RemoveFabric (stub — fabric state not cleared)");
        self.send_noc_response(addr, msg_header, proto_header).await
    }

    async fn send_noc_response(
        &self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
    ) -> Result<()> {
        let mut noc_resp = tlv::TlvBuffer::new();
        noc_resp.write_uint8(0, 0)?; // StatusCode = Success
        noc_resp.write_uint8(1, 1)?; // FabricIndex

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
        Ok(())
    }

    pub(crate) async fn handle_arm_failsafe(
        &mut self,
        addr: &std::net::SocketAddr,
        msg_header: &messages::MessageHeader,
        proto_header: &messages::ProtocolMessageHeader,
        invoke_tlv: &tlv::TlvItem,
    ) -> Result<()> {
        log::info!("IM: ArmFailsafe");
        invoke_tlv.dump(1);
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

        self.send_commissioning_reply(addr, &resp).await
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

        self.send_commissioning_reply(addr, &resp).await
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

        self.send_commissioning_reply(addr, &resp).await
    }
}
