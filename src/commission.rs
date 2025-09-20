use anyhow::{Context, Result};
use rand::RngCore;

use crate::{
    cert_matter, cert_x509, certmanager, controller::auth_sigma, fabric::Fabric, messages,
    retransmit, session, tlv, transport,
};

const CLUSTER_OPERATIONAL_CREDENTIALS: u32 = 0x3e;
const CMD_OPERATIONAL_CREDENTIALS_ADDTRUSTEDROOTCERTIFICATE: u32 = 0xb;
const CMD_OPERATIONAL_CREDENTIALS_ADDNOC: u32 = 0x6;
const CMD_OPERATIONAL_CSRREQUEST: u32 = 0x4;

const CLUSTER_GENERAL_COMMISSIONING: u32 = 0x30;
const CMD_GENERAL_COMMISSIONING_COMMISSIONINGCOMPLETE: u32 = 4;

async fn push_ca_cert(
    retrcrx: &mut retransmit::RetrContext<'_>,
    cm: &dyn certmanager::CertManager,
) -> Result<()> {
    let ca_pubkey = cm.get_ca_key()?.public_key().to_sec1_bytes();
    let ca_cert = cm.get_ca_cert()?;
    let mcert = cert_matter::convert_x509_bytes_to_matter(&ca_cert, &ca_pubkey)?;
    let mut tlv = tlv::TlvBuffer::new();
    tlv.write_octetstring(0, &mcert)?;
    let t1 = messages::im_invoke_request(
        0,
        CLUSTER_OPERATIONAL_CREDENTIALS,
        CMD_OPERATIONAL_CREDENTIALS_ADDTRUSTEDROOTCERTIFICATE,
        1,
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
    let t1 = messages::im_invoke_request(
        0,
        CLUSTER_OPERATIONAL_CREDENTIALS,
        CMD_OPERATIONAL_CREDENTIALS_ADDNOC,
        1,
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
) -> Result<x509_cert::request::CertReq> {
    let mut tlv = tlv::TlvBuffer::new();
    let mut random_csr_nonce = vec![0; 32];
    rand::thread_rng().fill_bytes(&mut random_csr_nonce);
    tlv.write_octetstring(0, &random_csr_nonce)?;
    let csr_request = messages::im_invoke_request(
        0,
        CLUSTER_OPERATIONAL_CREDENTIALS,
        CMD_OPERATIONAL_CSRREQUEST,
        1,
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
    connection: &transport::Connection,
    cm: &dyn certmanager::CertManager,
    node_id: u64,
    controller_id: u64,
    fabric: &Fabric,
) -> Result<session::Session> {
    let mut ses = auth_sigma(connection, fabric, cm, node_id, controller_id).await?;
    let t1 = messages::im_invoke_request(
        0,
        CLUSTER_GENERAL_COMMISSIONING,
        CMD_GENERAL_COMMISSIONING_COMMISSIONINGCOMPLETE,
        30,
        &[],
        false,
    )?;
    let mut retrctx = retransmit::RetrContext::new(connection, &mut ses);

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
    connection: &transport::Connection,
    session: &mut session::Session,
    fabric: &Fabric,
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
