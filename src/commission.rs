use anyhow::{Context, Result};
use rand::RngCore;

use crate::{
    cert_matter, cert_x509, certmanager, controller::auth_sigma, fabric::Fabric, messages,
    retransmit, session, tlv, transport::ConnectionTrait,
};

const CLUSTER_OPERATIONAL_CREDENTIALS: u32 = 0x3e;
const CMD_OPERATIONAL_CREDENTIALS_ADDTRUSTEDROOTCERTIFICATE: u32 = 0xb;
const CMD_OPERATIONAL_CREDENTIALS_ADDNOC: u32 = 0x6;
const CMD_OPERATIONAL_CSRREQUEST: u32 = 0x4;
//const CMD_OPERATIONAL_ATTESTATION_REQUEST: u32 = 0x0;
//const CMD_OPERATIONAL_CERTCHAIN_REQUEST: u32 = 0x2;

const CLUSTER_GENERAL_COMMISSIONING: u32 = 0x30;
const CMD_GENERAL_COMMISSIONING_ARMFAILSAFE: u32 = 0;
//const CMD_GENERAL_COMMISSIONING_SETREGULATORYCONFIG: u32 = 2;
const CMD_GENERAL_COMMISSIONING_COMMISSIONINGCOMPLETE: u32 = 4;

#[cfg(feature = "ble")]
const CLUSTER_NETWORK_COMMISSIONING: u32 = 0x31;
#[cfg(feature = "ble")]
const CMD_NETWORK_ADD_OR_UPDATE_WIFI: u32 = 2;
#[cfg(feature = "ble")]
const CMD_NETWORK_ADD_OR_UPDATE_THREAD: u32 = 3;
#[cfg(feature = "ble")]
const CMD_NETWORK_CONNECT: u32 = 6;

/// Credentials for the network the device should join after commissioning.
#[derive(Clone)]
pub enum NetworkCreds {
    /// Commission a Wi-Fi device: provide SSID and passphrase bytes.
    WiFi { ssid: Vec<u8>, creds: Vec<u8> },
    /// Commission a Thread device: provide the operational dataset bytes.
    Thread { dataset: Vec<u8> },
    /// Device is already on the IP network (Ethernet or pre-provisioned); skip
    /// NetworkCommissioning cluster writes.
    AlreadyOnNetwork,
}


/*async fn run_attestation(
    retrctx: &mut retransmit::RetrContext<'_>,
    exchange_base: u16,
) -> Result<()> {
    // CertificateChainRequest(PAI)
    {
        let mut tlv_buf = tlv::TlvBuffer::new();
        tlv_buf.write_uint8(0, 2)?; // certificateType = 2 = PAI
        let req = messages::im_invoke_request(
            0,
            CLUSTER_OPERATIONAL_CREDENTIALS,
            CMD_OPERATIONAL_CERTCHAIN_REQUEST,
            exchange_base,
            &tlv_buf.data,
            false,
        )?;
        retrctx.send(&req).await?;
        let _resp = retrctx.get_next_message().await.context("CertChainRequest PAI")?;
    }

    // CertificateChainRequest(DAC)
    {
        let mut tlv_buf = tlv::TlvBuffer::new();
        tlv_buf.write_uint8(0, 1)?; // certificateType = 1 = DAC
        let req = messages::im_invoke_request(
            0,
            CLUSTER_OPERATIONAL_CREDENTIALS,
            CMD_OPERATIONAL_CERTCHAIN_REQUEST,
            exchange_base.wrapping_add(1),
            &tlv_buf.data,
            false,
        )?;
        retrctx.send(&req).await?;
        let _resp = retrctx.get_next_message().await.context("CertChainRequest DAC")?;
    }

    // AttestationRequest
    {
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut tlv_buf = tlv::TlvBuffer::new();
        tlv_buf.write_octetstring(0, &nonce)?;
        let req = messages::im_invoke_request(
            0,
            CLUSTER_OPERATIONAL_CREDENTIALS,
            CMD_OPERATIONAL_ATTESTATION_REQUEST,
            exchange_base.wrapping_add(2),
            &tlv_buf.data,
            false,
        )?;
        retrctx.send(&req).await?;
        let _resp = retrctx.get_next_message().await.context("AttestationRequest")?;
    }

    Ok(())
}*/

async fn push_ca_cert(
    retrcrx: &mut retransmit::RetrContext<'_>,
    cm: &dyn certmanager::CertManager,
    exchange_id: u16,
) -> Result<()> {
    let ca_pubkey = cm.get_ca_key()?.public_key().to_sec1_bytes();
    let ca_cert = cm.get_ca_cert()?;
    let mcert = cert_matter::convert_x509_bytes_to_matter(&ca_cert, &ca_pubkey)?;
    log::debug!("AddTrustedRootCertificate: matter cert TLV ({} bytes): {}", mcert.len(),
        mcert.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""));
    let mut tlv = tlv::TlvBuffer::new();
    tlv.write_octetstring(0, &mcert)?;
    let t1 = messages::im_invoke_request(
        0,
        CLUSTER_OPERATIONAL_CREDENTIALS,
        CMD_OPERATIONAL_CREDENTIALS_ADDTRUSTEDROOTCERTIFICATE,
        exchange_id,
        &tlv.data,
        false,
    )?;
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
            "AddTrustedRootCertificate failed with status {}/{}",
            noc_status,
            noc_status_to_str(noc_status)
        ));
    }
    Ok(())
}

fn noc_status_to_str(status: u64) -> &'static str {
    match status {
        0 => "Success",
        1 => "InvalidPublicKey",
        2 => "InvalidNodeOpId",
        3 => "InvalidNOC",
        4 => "MissingCsr",
        5 => "TableFull",
        6 => "InvalidAdminSubject",
        7 => "?",
        8 => "?",
        9 => "FabricConflict",
        10 => "LabelConflict",
        11 => "InvalidFabricIndex",
        _ => "UnknownStatus",
    }
}

async fn push_device_cert(
    retrcrx: &mut retransmit::RetrContext<'_>,
    cm: &dyn certmanager::CertManager,
    csrd: x509_cert::request::CertReq,
    node_id: u64,
    controller_id: u64,
    fabric: &Fabric,
    exchange_id: u16,
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
    tlv.write_uint16(4, 101)?;
    let t1 = messages::im_invoke_request(
        0,
        CLUSTER_OPERATIONAL_CREDENTIALS,
        CMD_OPERATIONAL_CREDENTIALS_ADDNOC,
        exchange_id,
        &tlv.data,
        false,
    )?;
    retrcrx.send(&t1).await?;

    let resp = retrcrx.get_next_message().await?;
    let noc_status = {
        resp.tlv
            .get_int(&[1, 0, 0, 1, 0])
            .context("can't get status for AddNOC")?
    };
    if noc_status != 0 {
        return Err(anyhow::anyhow!("AddNOC failed with status {}/{}", noc_status, noc_status_to_str(noc_status)));
    }
    Ok(())
}

async fn send_csr(
    retrcrx: &mut retransmit::RetrContext<'_>,
    exchange_id: u16,
) -> Result<x509_cert::request::CertReq> {
    let mut tlv = tlv::TlvBuffer::new();
    let mut random_csr_nonce = vec![0; 32];
    rand::thread_rng().fill_bytes(&mut random_csr_nonce);
    tlv.write_octetstring(0, &random_csr_nonce)?;
    let csr_request = messages::im_invoke_request(
        0,
        CLUSTER_OPERATIONAL_CREDENTIALS,
        CMD_OPERATIONAL_CSRREQUEST,
        exchange_id,
        &tlv.data,
        false,
    )?;
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
    connection: &dyn ConnectionTrait,
    cm: &dyn certmanager::CertManager,
    node_id: u64,
    controller_id: u64,
    fabric: &Fabric,
) -> Result<session::Session> {
    // resumption ignored for now - we do not support resumption on connections used for commissioning
    let (ses, _resumption) = auth_sigma(connection, fabric, cm, node_id, controller_id).await?;
    let t1 = messages::im_invoke_request(
        0,
        CLUSTER_GENERAL_COMMISSIONING,
        CMD_GENERAL_COMMISSIONING_COMMISSIONINGCOMPLETE,
        30,
        &[],
        false,
    )?;
    let mut retrctx = retransmit::RetrContext::new(connection, &ses);

    retrctx.send(&t1).await?;
    let resp = retrctx.get_next_message().await?;
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

pub(crate) async fn commission(
    connection: &dyn ConnectionTrait,
    session: &mut session::Session,
    fabric: &Fabric,
    cm: &dyn certmanager::CertManager,
    node_id: u64,
    controller_id: u64,
) -> Result<session::Session> {
    // node operational credentials procedure
    let mut retrctx = retransmit::RetrContext::new(connection, session);
    let base: u16 = rand::random();

    arm_failsafe(&mut retrctx, 60, base).await?;

    let csrd = send_csr(&mut retrctx, base.wrapping_add(1)).await?;

    push_ca_cert(&mut retrctx, cm, base.wrapping_add(2)).await?;

    push_device_cert(&mut retrctx, cm, csrd, node_id, controller_id, fabric, base.wrapping_add(3)).await?;

    let ses = commissioning_complete(connection, cm, node_id, controller_id, fabric).await?;

    Ok(ses)
}

async fn arm_failsafe(
    retrctx: &mut retransmit::RetrContext<'_>,
    timeout_secs: u16,
    exchange_id: u16,
) -> Result<()> {
    let mut tlv_buf = tlv::TlvBuffer::new();
    tlv_buf.write_uint16(0, timeout_secs)?;
    tlv_buf.write_uint64(1, 0)?; // breadcrumb
    let req = messages::im_invoke_request(
        0,
        CLUSTER_GENERAL_COMMISSIONING,
        CMD_GENERAL_COMMISSIONING_ARMFAILSAFE,
        exchange_id,
        &tlv_buf.data,
        false,
    )?;
    retrctx.send(&req).await?;
    let resp = retrctx.get_next_message().await?;
    let status = resp.tlv.get_int(&[1, 0, 0, 1, 0]).context("ArmFailSafe: status missing")?;
    if status != 0 {
        return Err(anyhow::anyhow!("ArmFailSafe failed with status {}", status));
    }
    Ok(())
}

/*async fn set_regulatory_config(
    retrctx: &mut retransmit::RetrContext<'_>,
    exchange_id: u16,
) -> Result<()> {
    let mut tlv_buf = tlv::TlvBuffer::new();
    tlv_buf.write_uint8(0, 0)?;  // location type: Indoor
    tlv_buf.write_string(1, "XX")?; // regulatory location (placeholder)
    tlv_buf.write_uint64(2, 0)?;  // breadcrumb
    let req = messages::im_invoke_request(
        0,
        CLUSTER_GENERAL_COMMISSIONING,
        CMD_GENERAL_COMMISSIONING_SETREGULATORYCONFIG,
        exchange_id,
        &tlv_buf.data,
        false,
    )?;
    retrctx.send(&req).await?;
    let resp = retrctx.get_next_message().await?;
    let status = resp.tlv.get_int(&[1, 0, 0, 1, 0]).context("SetRegulatoryConfig: status missing")?;
    if status != 0 {
        return Err(anyhow::anyhow!("SetRegulatoryConfig failed with status {}", status));
    }
    Ok(())
}*/

#[cfg(feature = "ble")]
async fn add_or_update_wifi(
    retrctx: &mut retransmit::RetrContext<'_>,
    ssid: &[u8],
    creds: &[u8],
    exchange_id: u16,
) -> Result<Vec<u8>> {
    let mut tlv_buf = tlv::TlvBuffer::new();
    tlv_buf.write_octetstring(0, ssid)?;
    tlv_buf.write_octetstring(1, creds)?;
    let req = messages::im_invoke_request(
        0,
        CLUSTER_NETWORK_COMMISSIONING,
        CMD_NETWORK_ADD_OR_UPDATE_WIFI,
        exchange_id,
        &tlv_buf.data,
        false,
    )?;
    retrctx.send(&req).await?;
    let resp = retrctx.get_next_message().await?;
    let status = resp.tlv.get_int(&[1, 0, 0, 1, 0]).context("AddOrUpdateWifiNetwork: status missing")?;
    if status != 0 {
        return Err(anyhow::anyhow!("AddOrUpdateWifiNetwork failed with status {}", status));
    }
    Ok(ssid.to_vec())
}

#[cfg(feature = "ble")]
async fn add_or_update_thread(
    retrctx: &mut retransmit::RetrContext<'_>,
    dataset: &[u8],
    exchange_id: u16,
) -> Result<Vec<u8>> {
    let mut tlv_buf = tlv::TlvBuffer::new();
    tlv_buf.write_octetstring(0, dataset)?;
    let req = messages::im_invoke_request(
        0,
        CLUSTER_NETWORK_COMMISSIONING,
        CMD_NETWORK_ADD_OR_UPDATE_THREAD,
        exchange_id,
        &tlv_buf.data,
        false,
    )?;
    retrctx.send(&req).await?;
    let resp = retrctx.get_next_message().await?;
    let status = resp.tlv.get_int(&[1, 0, 0, 1, 0]).context("AddOrUpdateThreadNetwork: status missing")?;
    if status != 0 {
        return Err(anyhow::anyhow!("AddOrUpdateThreadNetwork failed with status {}", status));
    }
    // Return first 8 bytes as network ID (typically the Extended PAN ID)
    Ok(dataset[..dataset.len().min(8)].to_vec())
}

#[cfg(feature = "ble")]
async fn connect_network(
    retrctx: &mut retransmit::RetrContext<'_>,
    network_id: &[u8],
    exchange_id: u16,
) -> Result<()> {
    let mut tlv_buf = tlv::TlvBuffer::new();
    tlv_buf.write_octetstring(0, network_id)?;
    tlv_buf.write_uint64(1, 0)?; // breadcrumb
    let req = messages::im_invoke_request(
        0,
        CLUSTER_NETWORK_COMMISSIONING,
        CMD_NETWORK_CONNECT,
        exchange_id,
        &tlv_buf.data,
        false,
    )?;
    retrctx.send(&req).await?;
    let resp = retrctx.get_next_message().await?;
    let status = resp.tlv.get_int(&[1, 0, 0, 1, 0]).context("ConnectNetwork: status missing")?;
    if status != 0 {
        return Err(anyhow::anyhow!("ConnectNetwork failed with status {}", status));
    }
    Ok(())
}

#[cfg(feature = "ble")]
pub(crate) async fn commission_ble_phase(
    ble_connection: &dyn ConnectionTrait,
    pase_session: &mut session::Session,
    fabric: &Fabric,
    cm: &dyn certmanager::CertManager,
    node_id: u64,
    controller_id: u64,
    network_creds: &NetworkCreds,
) -> Result<()> {
    let mut retrctx = retransmit::RetrContext::new(ble_connection, pase_session);
    let base: u16 = rand::random();
    let e_arm      = base;
    //let e_reg      = base.wrapping_add(1);
    // run_attestation uses e_attest+0, e_attest+1, e_attest+2 (3 exchanges)
    //let e_attest   = base.wrapping_add(2);
    let e_csr      = base.wrapping_add(5);
    let e_ca       = base.wrapping_add(6);
    let e_noc      = base.wrapping_add(7);
    let e_net1     = base.wrapping_add(8);
    let e_net2     = base.wrapping_add(9);

    arm_failsafe(&mut retrctx, 60, e_arm).await.context("ArmFailSafe")?;
    log::debug!("Failsafe armed for 60 seconds");

    //set_regulatory_config(&mut retrctx, e_reg).await.context("SetRegulatoryConfig")?;
    //log::debug!("Regulatory configuration set");

    //run_attestation(&mut retrctx, e_attest).await.context("Attestation")?;
    //log::debug!("Attestation completed");

    let csrd = send_csr(&mut retrctx, e_csr).await?;
    log::debug!("CSR received");
    push_ca_cert(&mut retrctx, cm, e_ca).await?;
    log::debug!("CA certificate pushed");
    push_device_cert(&mut retrctx, cm, csrd, node_id, controller_id, fabric, e_noc).await?;
    log::debug!("Device certificate pushed");

    match network_creds {
        NetworkCreds::WiFi { ssid, creds } => {
            let net_id = add_or_update_wifi(&mut retrctx, ssid, creds, e_net1).await?;
            connect_network(&mut retrctx, &net_id, e_net2).await?;
            log::debug!("WiFi network connected");
            // Give the device time to join the network before the caller probes mDNS.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        NetworkCreds::Thread { dataset } => {
            let net_id = add_or_update_thread(&mut retrctx, dataset, e_net1).await?;
            connect_network(&mut retrctx, &net_id, e_net2).await?;
            log::debug!("Thread network connected");
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        NetworkCreds::AlreadyOnNetwork => {}
    }

    Ok(())
}

#[cfg(feature = "ble")]
pub(crate) async fn commissioning_complete_udp(
    udp_connection: &dyn ConnectionTrait,
    cm: &dyn certmanager::CertManager,
    node_id: u64,
    controller_id: u64,
    fabric: &Fabric,
) -> Result<session::Session> {
    commissioning_complete(udp_connection, cm, node_id, controller_id, fabric).await
}
