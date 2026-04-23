use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};
use rand::RngCore;
use std::io::Write;

use crate::messages::ProtocolMessageHeader;
use crate::tlv;

fn device_flags(ack: i64) -> u8 {
    let mut flags = ProtocolMessageHeader::FLAG_RELIABILITY;
    if ack >= 0 {
        flags |= ProtocolMessageHeader::FLAG_ACK;
    }
    flags
}

fn device_flags_initiator() -> u8 {
    ProtocolMessageHeader::FLAG_INITIATOR | ProtocolMessageHeader::FLAG_RELIABILITY
}

pub fn pbkdf_resp(exchange: u16, responder_session: u16, salt: &[u8], iterations: u32, ack: i64, initiator_random: &[u8]) -> Result<Vec<u8>> {
    let mut b = ProtocolMessageHeader {
        exchange_flags: device_flags(ack),
        opcode: ProtocolMessageHeader::OPCODE_PBKDF_RESP,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
        ack_counter: ack as u32,
    }
    .encode()?;
    let mut tlv = tlv::TlvBuffer::new();
    tlv.write_anon_struct()?;
    let mut responder_random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut responder_random);
    tlv.write_octetstring(1, initiator_random)?;
    tlv.write_octetstring(2, &responder_random)?;
    tlv.write_uint16(3, responder_session)?;
    tlv.write_struct(4)?;
    tlv.write_uint32(1, iterations)?;
    tlv.write_octetstring(2, salt)?;
    tlv.write_struct_end()?;
    tlv.write_struct_end()?;
    b.write_all(&tlv.data)?;
    Ok(b)
}

pub fn pake2(exchange: u16, pb: &[u8], cb: &[u8], ack: i64) -> Result<Vec<u8>> {
    let mut b = ProtocolMessageHeader {
        exchange_flags: device_flags(ack),
        opcode: ProtocolMessageHeader::OPCODE_PASE_PAKE2,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
        ack_counter: ack as u32,
    }
    .encode()?;
    let mut tlv = tlv::TlvBuffer::new();
    tlv.write_anon_struct()?;
    tlv.write_octetstring(1, pb)?;
    tlv.write_octetstring(2, cb)?;
    tlv.write_struct_end()?;
    b.write_all(&tlv.data)?;
    Ok(b)
}

pub fn status_report(exchange: u16, general_code: u16, protocol_id: u32, protocol_code: u16, ack: i64) -> Result<Vec<u8>> {
    let mut b = ProtocolMessageHeader {
        exchange_flags: device_flags(ack),
        opcode: ProtocolMessageHeader::OPCODE_STATUS,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
        ack_counter: ack as u32,
    }
    .encode()?;
    b.write_u16::<LittleEndian>(general_code)?;
    b.write_u32::<LittleEndian>(protocol_id)?;
    b.write_u16::<LittleEndian>(protocol_code)?;
    Ok(b)
}

pub fn sigma2_msg(exchange: u16, payload: &[u8], ack: i64) -> Result<Vec<u8>> {
    let mut b = ProtocolMessageHeader {
        exchange_flags: device_flags(ack),
        opcode: ProtocolMessageHeader::OPCODE_CASE_SIGMA2,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
        ack_counter: ack as u32,
    }
    .encode()?;
    b.write_all(payload)?;
    Ok(b)
}

pub fn device_ack(exchange: u16, ack: u32) -> Result<Vec<u8>> {
    ProtocolMessageHeader {
        exchange_flags: ProtocolMessageHeader::FLAG_ACK,
        opcode: ProtocolMessageHeader::OPCODE_ACK,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
        ack_counter: ack,
    }
    .encode()
}

pub fn device_ack_initiator(exchange: u16, ack: u32) -> Result<Vec<u8>> {
    ProtocolMessageHeader {
        exchange_flags: ProtocolMessageHeader::FLAG_INITIATOR | ProtocolMessageHeader::FLAG_ACK,
        opcode: ProtocolMessageHeader::OPCODE_ACK,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
        ack_counter: ack,
    }
    .encode()
}

/*pub fn im_status_response(exchange: u16, status: u8, ack: i64) -> Result<Vec<u8>> {
    let b = ProtocolMessageHeader {
        exchange_flags: device_flags(ack),
        opcode: ProtocolMessageHeader::INTERACTION_OPCODE_STATUS_RESP,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
        ack_counter: if ack >= 0 { ack as u32 } else { 0 },
    }
    .encode()?;
    let mut tlv = tlv::TlvBuffer::from_vec(b);
    tlv.write_anon_struct()?;
    tlv.write_uint8(0, status)?;
    tlv.write_struct_end()?;
    Ok(tlv.data)
}*/

pub fn im_subscribe_response(subscription_id: u32, exchange: u16, ack: i64, max_interval: u16) -> Result<Vec<u8>> {
    let b = ProtocolMessageHeader {
        exchange_flags: device_flags(ack),
        opcode: ProtocolMessageHeader::INTERACTION_OPCODE_SUBSCRIBE_RESP,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
        ack_counter: if ack >= 0 { ack as u32 } else { 0 },
    }
    .encode()?;
    let mut tlv = tlv::TlvBuffer::from_vec(b);
    tlv.write_anon_struct()?;
    tlv.write_uint32(0, subscription_id)?;
    tlv.write_uint16(2, max_interval)?;
    tlv.write_struct_end()?;
    Ok(tlv.data)
}

pub fn im_invoke_response_data(
    exchange: u16,
    endpoint: u16,
    cluster: u32,
    command: u32,
    response_fields_tlv: &[u8],
    ack: i64,
) -> Result<Vec<u8>> {
    let b = ProtocolMessageHeader {
        exchange_flags: device_flags(ack),
        opcode: ProtocolMessageHeader::INTERACTION_OPCODE_INVOKE_RESP,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
        ack_counter: ack as u32,
    }
    .encode()?;

    let mut tlv = tlv::TlvBuffer::from_vec(b);
    tlv.write_anon_struct()?;
    tlv.write_bool(0, false)?; // SuppressResponse
    tlv.write_array(1)?; // InvokeResponses
    tlv.write_anon_struct()?; // InvokeResponseIB
    tlv.write_struct(0)?; // CommandDataIB (tag 0)
    tlv.write_list(0)?; // CommandPathIB
    tlv.write_uint16(0, endpoint)?;
    tlv.write_uint32(1, cluster)?;
    tlv.write_uint32(2, command)?;
    tlv.write_struct_end()?; // end CommandPathIB
    tlv.write_struct(1)?; // CommandFields
    tlv.write_raw(response_fields_tlv)?;
    tlv.write_struct_end()?; // end CommandFields
    tlv.write_struct_end()?; // end CommandDataIB
    tlv.write_struct_end()?; // end InvokeResponseIB
    tlv.write_struct_end()?; // end InvokeResponses array
    tlv.write_struct_end()?; // end top-level struct
    Ok(tlv.data)
}

/// One entry in a ReportData response - either actual attribute data or a status code.
#[derive(Clone)]
pub(crate) enum AttrReport {
    Data {
        endpoint: u16,
        cluster: u32,
        attribute: u32,
        value_tlv: Vec<u8>,
    },
    Status {
        endpoint: u16,
        cluster: u32,
        attribute: u32,
        status: u8,
    },
}

pub fn im_report_data(exchange: u16, reports: &[AttrReport], ack: i64, subscription_id: Option<u32>, more_chunks: bool) -> Result<Vec<u8>> {
    let b = ProtocolMessageHeader {
        exchange_flags: device_flags(ack),
        opcode: ProtocolMessageHeader::INTERACTION_OPCODE_REPORT_DATA,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
        ack_counter: ack as u32,
    }
    .encode()?;

    let mut tlv = tlv::TlvBuffer::from_vec(b);
    tlv.write_anon_struct()?;             // top-level
    if let Some(sub_id) = subscription_id {
        tlv.write_uint32(0, sub_id)?;     // tag 0: SubscriptionID
    }
    tlv.write_array(1)?;                  // tag 1: AttributeReportIBs
    for report in reports {
        match report {
            AttrReport::Data { endpoint, cluster, attribute, value_tlv } => {
                tlv.write_anon_struct()?;         // AttributeReportIB
                tlv.write_struct(1)?;             // tag 1: AttributeDataIB
                tlv.write_uint32(0, 0)?;          //   tag 0: DataVersion (0)
                tlv.write_list(1)?;               //   tag 1: AttributePathIB
                tlv.write_uint16(2, *endpoint)?;  //     tag 2: Endpoint
                tlv.write_uint32(3, *cluster)?;   //     tag 3: ClusterID
                tlv.write_uint32(4, *attribute)?; //     tag 4: AttributeID
                tlv.write_struct_end()?;          //   end AttributePathIB
                tlv.write_raw(value_tlv)?;        //   tag 2: Data (pre-encoded)
                tlv.write_struct_end()?;          // end AttributeDataIB
                tlv.write_struct_end()?;          // end AttributeReportIB
            }
            AttrReport::Status { endpoint, cluster, attribute, status } => {
                tlv.write_anon_struct()?;         // AttributeReportIB
                tlv.write_struct(0)?;             // tag 0: AttributeStatusIB
                tlv.write_list(0)?;               //   tag 0: AttributePathIB
                tlv.write_uint16(2, *endpoint)?;  //     tag 2: Endpoint
                tlv.write_uint32(3, *cluster)?;   //     tag 3: ClusterID
                tlv.write_uint32(4, *attribute)?; //     tag 4: AttributeID
                tlv.write_struct_end()?;          //   end AttributePathIB
                tlv.write_struct(1)?;             //   tag 1: StatusIB
                tlv.write_uint8(0, *status)?;     //     tag 0: Status
                tlv.write_struct_end()?;          //   end StatusIB
                tlv.write_struct_end()?;          // end AttributeStatusIB
                tlv.write_struct_end()?;          // end AttributeReportIB
            }
        }
    }
    tlv.write_struct_end()?;              // end array
    if more_chunks {
        tlv.write_bool(3, true)?;         // tag 3: MoreChunkedMessages
    }
    tlv.write_struct_end()?;              // end top-level
    Ok(tlv.data)
}

pub fn im_report_data_unsolicited(exchange: u16, reports: &[AttrReport], subscription_id: u32) -> Result<Vec<u8>> {
    let b = ProtocolMessageHeader {
        exchange_flags: device_flags_initiator(),
        opcode: ProtocolMessageHeader::INTERACTION_OPCODE_REPORT_DATA,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
        ack_counter: 0,
    }
    .encode()?;

    let mut tlv = tlv::TlvBuffer::from_vec(b);
    tlv.write_anon_struct()?;
    tlv.write_uint32(0, subscription_id)?;    // tag 0: SubscriptionID
    tlv.write_array(1)?;                       // tag 1: AttributeReportIBs
    for report in reports {
        match report {
            AttrReport::Data { endpoint, cluster, attribute, value_tlv } => {
                tlv.write_anon_struct()?;
                tlv.write_struct(1)?;
                tlv.write_uint32(0, 0)?;
                tlv.write_list(1)?;
                tlv.write_uint16(2, *endpoint)?;
                tlv.write_uint32(3, *cluster)?;
                tlv.write_uint32(4, *attribute)?;
                tlv.write_struct_end()?;
                tlv.write_raw(value_tlv)?;
                tlv.write_struct_end()?;
                tlv.write_struct_end()?;
            }
            AttrReport::Status { endpoint, cluster, attribute, status } => {
                tlv.write_anon_struct()?;
                tlv.write_struct(0)?;
                tlv.write_list(0)?;
                tlv.write_uint16(2, *endpoint)?;
                tlv.write_uint32(3, *cluster)?;
                tlv.write_uint32(4, *attribute)?;
                tlv.write_struct_end()?;
                tlv.write_struct(1)?;
                tlv.write_uint8(0, *status)?;
                tlv.write_struct_end()?;
                tlv.write_struct_end()?;
                tlv.write_struct_end()?;
            }
        }
    }
    tlv.write_struct_end()?;   // end array
    tlv.write_struct_end()?;   // end top-level
    Ok(tlv.data)
}

#[allow(dead_code)]
pub fn im_report_data_status(
    exchange: u16,
    endpoint: u16,
    cluster: u32,
    attribute: u32,
    status: u8,
    ack: i64,
) -> Result<Vec<u8>> {
    im_report_data(exchange, &[AttrReport::Status { endpoint, cluster, attribute, status }], ack, None, false)
}

#[allow(dead_code)]
pub fn im_report_data_multi_status(
    exchange: u16,
    attrs: &[(u16, u32, u32, u8)],
    ack: i64,
) -> Result<Vec<u8>> {
    let reports: Vec<AttrReport> = attrs
        .iter()
        .map(|&(endpoint, cluster, attribute, status)| {
            AttrReport::Status { endpoint, cluster, attribute, status }
        })
        .collect();
    im_report_data(exchange, &reports, ack, None, false)
}

pub fn im_invoke_response_status(
    exchange: u16,
    endpoint: u16,
    cluster: u32,
    command: u32,
    status: u16,
    ack: i64,
) -> Result<Vec<u8>> {
    let b = ProtocolMessageHeader {
        exchange_flags: device_flags(ack),
        opcode: ProtocolMessageHeader::INTERACTION_OPCODE_INVOKE_RESP,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
        ack_counter: ack as u32,
    }
    .encode()?;

    let mut tlv = tlv::TlvBuffer::from_vec(b);
    tlv.write_anon_struct()?;
    tlv.write_bool(0, false)?;
    tlv.write_array(1)?;
    tlv.write_anon_struct()?;
    tlv.write_struct(1)?; // CommandStatusIB (tag 1)
    tlv.write_list(0)?; // CommandPathIB
    tlv.write_uint16(0, endpoint)?;
    tlv.write_uint32(1, cluster)?;
    tlv.write_uint32(2, command)?;
    tlv.write_struct_end()?; // end CommandPathIB
    tlv.write_struct(1)?; // StatusIB
    tlv.write_uint16(0, status)?;
    tlv.write_struct_end()?; // end StatusIB
    tlv.write_struct_end()?; // end CommandStatusIB
    tlv.write_struct_end()?; // end InvokeResponseIB
    tlv.write_struct_end()?; // end InvokeResponses array
    tlv.write_struct_end()?; // end top-level struct
    Ok(tlv.data)
}

/// WriteResponse with success status for each written attribute path.
pub fn im_write_response_success(exchange: u16, ack: i64, paths: &[(u16, u32, u32)]) -> Result<Vec<u8>> {
    let b = ProtocolMessageHeader {
        exchange_flags: device_flags(ack),
        opcode: ProtocolMessageHeader::INTERACTION_OPCODE_WRITE_RESP,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
        ack_counter: ack as u32,
    }
    .encode()?;

    let mut tlv = tlv::TlvBuffer::from_vec(b);
    tlv.write_anon_struct()?;
    tlv.write_array(0)?;  // tag 0: WriteAttributeStatusIBs
    for &(endpoint, cluster, attribute) in paths {
        // WriteAttributeStatusIB: tag 0 = AttributePathIB (list), tag 1 = StatusIB (struct)
        tlv.write_anon_struct()?;       // WriteAttributeStatusIB
        tlv.write_list(0)?;             // tag 0: AttributePathIB
        tlv.write_uint16(2, endpoint)?; //   tag 2: Endpoint
        tlv.write_uint32(3, cluster)?;  //   tag 3: Cluster
        tlv.write_uint32(4, attribute)?;//   tag 4: Attribute
        tlv.write_struct_end()?;        // end AttributePathIB
        tlv.write_struct(1)?;           // tag 1: StatusIB
        tlv.write_uint8(0, 0)?;         //   tag 0: Status = SUCCESS (0)
        tlv.write_struct_end()?;        // end StatusIB
        tlv.write_struct_end()?;        // end WriteAttributeStatusIB
    }
    tlv.write_struct_end()?;  // end array
    tlv.write_struct_end()?;  // end top-level struct
    Ok(tlv.data)
}
