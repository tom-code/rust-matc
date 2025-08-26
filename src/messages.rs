use anyhow::{Context, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use core::fmt;
use rand::RngCore;
use std::io::{Read, Write};

use crate::tlv::{self, TlvItem, TlvItemEnc, TlvItemValueEnc};

#[derive(Debug)]
pub struct MessageHeader {
    pub flags: u8,
    pub security_flags: u8,
    pub session_id: u16,
    pub message_counter: u32,
    pub source_node_id: Option<Vec<u8>>,
    pub destination_node_id: Option<Vec<u8>>,
}

impl MessageHeader {
    const FLAG_SRC_PRESENT: u8 = 4;
    const DSIZ_64: u8 = 1;
    const DSIZ_16: u8 = 2;
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut flags: u8 = 0;
        if self.source_node_id.as_ref().is_some_and(|x| x.len() == 8) {
            flags |= Self::FLAG_SRC_PRESENT;
        }
        if let Some(destination_node_id) = &self.destination_node_id {
            if destination_node_id.len() == 2 {
                flags |= Self::DSIZ_16
            } else if destination_node_id.len() == 8 {
                flags |= Self::DSIZ_64
            }
        }
        let mut out = Vec::with_capacity(1024);
        out.write_u8(flags)?;
        out.write_u16::<LittleEndian>(self.session_id)?;
        out.write_u8(self.security_flags)?;
        out.write_u32::<LittleEndian>(self.message_counter)?;
        if let Some(sn) = &self.source_node_id {
            if sn.len() == 8 {
                out.write_all(sn)?;
            }
        }
        if let Some(destination_node_id) = &self.destination_node_id {
            out.write_all(destination_node_id)?;
        }
        Ok(out)
    }
    pub fn decode(data: &[u8]) -> Result<(Self, Vec<u8>)> {
        let mut cursor = std::io::Cursor::new(data);
        let flags = cursor.read_u8()?;
        let session_id = cursor.read_u16::<LittleEndian>()?;
        let security_flags = cursor.read_u8()?;
        let message_counter = cursor.read_u32::<LittleEndian>()?;
        let source_node_id = if (flags & Self::FLAG_SRC_PRESENT) != 0 {
            let mut sn = vec![0; 8];
            cursor.read_exact(sn.as_mut())?;
            Some(sn)
        } else {
            None
        };
        let destination_node_id = if (flags & 3) != 0 {
            let dst_size = match flags & 3 {
                Self::DSIZ_64 => 8,
                Self::DSIZ_16 => 2,
                _ => 0,
            };
            if dst_size > 0 {
                let mut dn = vec![0; dst_size];
                cursor.read_exact(dn.as_mut())?;
                Some(dn)
            } else {
                None
            }
        } else {
            None
        };
        let mut rest = Vec::new();
        cursor.read_to_end(&mut rest)?;
        Ok((
            Self {
                flags,
                security_flags,
                session_id,
                message_counter,
                source_node_id,
                destination_node_id,
            },
            rest,
        ))
    }
}

/*#[derive(Debug)]
enum SecChannelOpcode {
    None = 0x0,
    Ack = 0x10,
    PbkdfReq = 0x20,
    PbkdfResp = 0x21,
    Pake1 = 0x22,
    Pake2 = 0x23,
    Pake3 = 0x24,
    Sigma1 = 0x30,
    Sigma2 = 0x31,
    Sigma3 = 0x32,
    Status = 0x40,
}*/

#[derive(Debug)]
pub struct ProtocolMessageHeader {
    exchange_flags: u8,
    pub opcode: u8,
    pub exchange_id: u16,
    pub protocol_id: u16,
    pub ack_counter: u32,
}

impl ProtocolMessageHeader {
    pub const FLAG_INITIATOR: u8 = 1;
    pub const FLAG_ACK: u8 = 2;
    pub const FLAG_RELIABILITY: u8 = 4;

    pub const OPCODE_ACK: u8 = 0x10;
    pub const OPCODE_PBKDF_REQ: u8 = 0x20;
    pub const OPCODE_PBKDF_RESP: u8 = 0x21;
    pub const OPCODE_PASE_PAKE1: u8 = 0x22;
    pub const OPCODE_PASE_PAKE2: u8 = 0x23;
    pub const OPCODE_PASE_PAKE3: u8 = 0x24;
    pub const OPCODE_CASE_SIGMA1: u8 = 0x30;
    pub const OPCODE_CASE_SIGMA2: u8 = 0x31;
    pub const OPCODE_CASE_SIGMA3: u8 = 0x32;
    pub const OPCODE_STATUS: u8 = 0x40;

    pub const INTERACTION_OPCODE_STATUS_RESP: u8 = 0x1;
    pub const INTERACTION_OPCODE_READ_REQ: u8 = 0x2;
    pub const INTERACTION_OPCODE_REPORT_DATA: u8 = 0x5;
    pub const INTERACTION_OPCODE_INVOKE_REQ: u8 = 0x8;
    pub const INTERACTION_OPCODE_INVOKE_RESP: u8 = 0x9;
    pub const INTERACTION_OPCODE_TIMED_REQ: u8 = 0xa;

    pub const PROTOCOL_ID_SECURE_CHANNEL: u16 = 0;
    pub const PROTOCOL_ID_INTERACTION: u16 = 1;

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(1024);
        out.write_u8(self.exchange_flags)?;
        out.write_u8(self.opcode)?;
        out.write_u16::<LittleEndian>(self.exchange_id)?;
        out.write_u16::<LittleEndian>(self.protocol_id)?;
        if (self.exchange_flags & Self::FLAG_ACK) != 0 {
            out.write_u32::<LittleEndian>(self.ack_counter)?;
        }
        Ok(out)
    }
    pub fn decode(data: &[u8]) -> Result<(Self, Vec<u8>)> {
        let mut cursor = std::io::Cursor::new(data);
        let exchange_flags = cursor.read_u8()?;
        let opcode = cursor.read_u8()?;
        let exchange_id = cursor.read_u16::<LittleEndian>()?;
        let protocol_id = cursor.read_u16::<LittleEndian>()?;
        let mut ack_counter = 0;
        if (exchange_flags & Self::FLAG_ACK) != 0 {
            ack_counter = cursor.read_u32::<LittleEndian>()?;
        }
        let mut rest = Vec::new();
        cursor.read_to_end(&mut rest)?;
        Ok((
            Self {
                exchange_flags,
                opcode,
                exchange_id,
                protocol_id,
                ack_counter,
            },
            rest,
        ))
    }
}


#[derive(Debug, Clone, Copy)]
pub enum SecureChannelGeneralCode {
    Success = 0,
    Failure = 1,
    BadPrecondition = 2,
    OutOfRange = 3,
    BadRequest = 4,
    Unsupported = 5,
    Unexpected = 6,
    ResourceExhausted = 7,
    Busy = 8,
    Timeout = 9,
    Continue = 10,
    Aborted = 11,
    InvalidArgument = 12,
    NotFound = 13,
    AlreadyExists = 14,
    PermissionDenied = 15,
    DataLoss = 16,
    MessageTooLarge = 17,
    Unknown = 0xffff
}

impl From<u16> for SecureChannelGeneralCode {
    fn from(value: u16) -> Self {
        match value {
            0 => SecureChannelGeneralCode::Success,
            1 => SecureChannelGeneralCode::Failure,
            2 => SecureChannelGeneralCode::BadPrecondition,
            3 => SecureChannelGeneralCode::OutOfRange,
            4 => SecureChannelGeneralCode::BadRequest,
            5 => SecureChannelGeneralCode::Unsupported,
            6 => SecureChannelGeneralCode::Unexpected,
            7 => SecureChannelGeneralCode::ResourceExhausted,
            8 => SecureChannelGeneralCode::Busy,
            9 => SecureChannelGeneralCode::Timeout,
            10 => SecureChannelGeneralCode::Continue,
            11 => SecureChannelGeneralCode::Aborted,
            12 => SecureChannelGeneralCode::InvalidArgument,
            13 => SecureChannelGeneralCode::NotFound,
            14 => SecureChannelGeneralCode::AlreadyExists,
            15 => SecureChannelGeneralCode::PermissionDenied,
            16 => SecureChannelGeneralCode::DataLoss,
            17 => SecureChannelGeneralCode::MessageTooLarge,
            _ => SecureChannelGeneralCode::Unknown
        }
    }
}

impl std::fmt::Display for SecureChannelGeneralCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecureChannelGeneralCode::Success => write!(f, "SUCCESS"),
            SecureChannelGeneralCode::Failure => write!(f, "FAILURE"),
            SecureChannelGeneralCode::BadPrecondition => write!(f, "BAD_PRECONDITION"),
            SecureChannelGeneralCode::OutOfRange => write!(f, "OUT_OF_RANGE"),
            SecureChannelGeneralCode::BadRequest => write!(f, "BAD_REQUEST"),
            SecureChannelGeneralCode::Unsupported => write!(f, "UNSUPPORTED"),
            SecureChannelGeneralCode::Unexpected => write!(f, "UNEXPECTED"),
            SecureChannelGeneralCode::ResourceExhausted => write!(f, "RESOURCE_EXHAUSTED"),
            SecureChannelGeneralCode::Busy => write!(f, "BUSY"),
            SecureChannelGeneralCode::Timeout => write!(f, "TIMEOUT"),
            SecureChannelGeneralCode::Continue => write!(f, "CONTINUE"),
            SecureChannelGeneralCode::Aborted => write!(f, "ABORTED"),
            SecureChannelGeneralCode::InvalidArgument => write!(f, "INVALID_ARGUMENT"),
            SecureChannelGeneralCode::NotFound => write!(f, "NOT_FOUND"),
            SecureChannelGeneralCode::AlreadyExists => write!(f, "ALREADY_EXISTS"),
            SecureChannelGeneralCode::PermissionDenied => write!(f, "PERMISSION_DENIED"),
            SecureChannelGeneralCode::DataLoss => write!(f, "DATA_LOSS"),
            SecureChannelGeneralCode::MessageTooLarge => write!(f, "MESSAGE_TOO_LARGE"),
            SecureChannelGeneralCode::Unknown => write!(f, "UNKNOWN {}", *self as u16),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SecureChannelProtocolCode {
    SessionEstablishmentSuccess = 0,
    NoSharedTrustRoots = 1,
    InvalidParameter = 2,
    CloseSession = 3,
    Busy = 4,
    RequiredCatMismatch = 5,
    Unknown = 0xffff
}

impl std::fmt::Display for SecureChannelProtocolCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecureChannelProtocolCode::SessionEstablishmentSuccess => write!(f, "SESSION_ESTABLISHMENT_SUCCESS"),
            SecureChannelProtocolCode::NoSharedTrustRoots => write!(f, "NO_SHARED_TRUST_ROOTS"),
            SecureChannelProtocolCode::InvalidParameter => write!(f, "INVALID_PARAMETER"),
            SecureChannelProtocolCode::CloseSession => write!(f, "CLOSE_SESSION"),
            SecureChannelProtocolCode::Busy => write!(f, "BUSY"),
            SecureChannelProtocolCode::RequiredCatMismatch => write!(f, "REQUIRED_CAT_MISMATCH"),
            SecureChannelProtocolCode::Unknown => write!(f, "UNKNOWN {}", *self as u16),
        }
    }
}

impl From<u16> for SecureChannelProtocolCode {
    fn from(value: u16) -> Self {
        match value {
            0 => SecureChannelProtocolCode::SessionEstablishmentSuccess,
            1 => SecureChannelProtocolCode::NoSharedTrustRoots,
            2 => SecureChannelProtocolCode::InvalidParameter,
            3 => SecureChannelProtocolCode::CloseSession,
            4 => SecureChannelProtocolCode::Busy,
            5 => SecureChannelProtocolCode::RequiredCatMismatch,
            _ => SecureChannelProtocolCode::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StatusReportInfo {
    general_code: u16,
    protocol_id: u32,
    protocol_code: u16,
}
impl std::fmt::Display for StatusReportInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.general_code == 0 {
            return write!(f, "StatusReportInfo: OK");
        }
        let gc = Into::<SecureChannelGeneralCode>::into(self.general_code);
        match self.protocol_id as u16{
            ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL => {
                let pc = Into::<SecureChannelProtocolCode>::into(self.protocol_code);
                write!(
                    f,
                    "StatusReportInfo: general_code={}, protocol_id={}, protocol_code={}",
                    gc, self.protocol_id, pc
                )

            },
            _ => {
                write!(f, "StatusReportInfo: general_code={}, protocol_id={}, protocol_code={}",
                    gc, self.protocol_id, self.protocol_code
                )
            }

        }
    }
}
impl StatusReportInfo {
    fn parse(data: &[u8]) -> Result<Self> {
        let mut cursor = std::io::Cursor::new(data);
        let general_code = cursor.read_u16::<LittleEndian>()?;
        let protocol_id = cursor.read_u32::<LittleEndian>()?;
        let protocol_code = cursor.read_u16::<LittleEndian>()?;
        Ok(Self {
            general_code,
            protocol_id,
            protocol_code,
        })
    }
    pub fn is_ok(&self) -> bool {
        self.general_code == 0 && self.protocol_id == 0 && self.protocol_code == 0
    }
}

pub struct Message {
    pub message_header: MessageHeader,
    pub protocol_header: ProtocolMessageHeader,
    pub payload: Vec<u8>,
    pub tlv: TlvItem,
    pub status_report_info: Option<StatusReportInfo>,
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Message")
            .field("message_header", &self.message_header)
            .field("protocol_header", &self.protocol_header)
            .field("payload", &hex::encode(&self.payload))
            .field("tlv", &self.tlv)
            .field("status_report_info", &self.status_report_info)
            .finish()
    }
}

impl Message {
    pub fn decode(data: &[u8]) -> Result<Self> {
        let (message_header, rest) = MessageHeader::decode(data)?;
        let (protocol_header, rest) = ProtocolMessageHeader::decode(&rest)?;
        if (protocol_header.protocol_id == ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL)
            && (protocol_header.opcode == ProtocolMessageHeader::OPCODE_STATUS)
        {
            let status_report_info = StatusReportInfo::parse(&rest)?;
            return Ok(Self {
                message_header,
                protocol_header,
                payload: rest,
                tlv: TlvItem {
                    tag: 0,
                    value: tlv::TlvItemValue::Invalid(),
                },
                status_report_info: Some(status_report_info),
            });
        }
        let tlv = tlv::decode_tlv(&rest)?;
        Ok(Self {
            message_header,
            protocol_header,
            payload: rest,
            tlv,
            status_report_info: None,
        })
    }
}

pub fn ack(exchange: u16, ack: i64) -> Result<Vec<u8>> {
    let mut flags = ProtocolMessageHeader::FLAG_INITIATOR;
    flags |= ProtocolMessageHeader::FLAG_ACK;
    ProtocolMessageHeader {
        exchange_flags: flags,
        opcode: ProtocolMessageHeader::OPCODE_ACK,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
        ack_counter: ack as u32,
    }
    .encode()
}

pub fn pbkdf_req(exchange: u16) -> Result<Vec<u8>> {
    let mut b = ProtocolMessageHeader {
        exchange_flags: ProtocolMessageHeader::FLAG_INITIATOR
            | ProtocolMessageHeader::FLAG_RELIABILITY,
        opcode: ProtocolMessageHeader::OPCODE_PBKDF_REQ,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
        ack_counter: 0,
    }
    .encode()?;
    let mut tlv = tlv::TlvBuffer::new();
    tlv.write_anon_struct()?;
    let mut initiator_random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut initiator_random);
    tlv.write_octetstring(0x1, &initiator_random)?;
    tlv.write_uint16(2, 1)?;
    tlv.write_uint8(3, 0)?;
    tlv.write_bool(4, false)?;
    tlv.write_struct_end()?;
    b.write_all(&tlv.data)?;
    Ok(b)
}

pub fn pake1(exchange: u16, key: &[u8], ack: i64) -> Result<Vec<u8>> {
    let mut flags = ProtocolMessageHeader::FLAG_INITIATOR | ProtocolMessageHeader::FLAG_RELIABILITY;
    if ack >= 0 {
        flags |= ProtocolMessageHeader::FLAG_ACK
    }
    let mut b = ProtocolMessageHeader {
        exchange_flags: flags,
        opcode: ProtocolMessageHeader::OPCODE_PASE_PAKE1,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
        ack_counter: ack as u32,
    }
    .encode()?;

    let tlv = TlvItemEnc {
        tag: 0,
        value: TlvItemValueEnc::StructAnon(vec![TlvItemEnc {
            tag: 1,
            value: TlvItemValueEnc::OctetString(key.to_owned()),
        }]),
    }
    .encode()?;
    b.write_all(&tlv)?;

    Ok(b)
}

pub fn pake3(exchange: u16, key: &[u8], ack: i64) -> Result<Vec<u8>> {
    let mut flags = 0x5;
    if ack >= 0 {
        flags |= 2
    }
    let mut b = ProtocolMessageHeader {
        exchange_flags: flags,
        opcode: ProtocolMessageHeader::OPCODE_PASE_PAKE3,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
        ack_counter: ack as u32,
    }
    .encode()?;
    let mut tlv = tlv::TlvBuffer::new();
    tlv.write_anon_struct()?;
    tlv.write_octetstring(0x1, key)?;
    tlv.write_struct_end()?;

    b.write_all(&tlv.data)?;
    Ok(b)
}

pub fn sigma1(exchange: u16, payload: &[u8]) -> Result<Vec<u8>> {
    let mut b = ProtocolMessageHeader {
        exchange_flags: 5,
        opcode: ProtocolMessageHeader::OPCODE_CASE_SIGMA1,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
        ack_counter: 0,
    }
    .encode()?;
    b.write_all(payload)?;
    Ok(b)
}

pub fn sigma3(exchange: u16, payload: &[u8]) -> Result<Vec<u8>> {
    let mut b = ProtocolMessageHeader {
        exchange_flags: 5,
        opcode: ProtocolMessageHeader::OPCODE_CASE_SIGMA3,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
        ack_counter: 0,
    }
    .encode()?;
    b.write_all(payload)?;
    Ok(b)
}

pub fn im_invoke_request(
    endpoint: u16,
    cluster: u32,
    command: u32,
    exchange_id: u16,
    payload: &[u8],
    timed: bool,
) -> Result<Vec<u8>> {
    let b = ProtocolMessageHeader {
        exchange_flags: 5,
        opcode: ProtocolMessageHeader::INTERACTION_OPCODE_INVOKE_REQ,
        exchange_id,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
        ack_counter: 0,
    }
    .encode()?;

    let mut tlv = tlv::TlvBuffer::from_vec(b);
    tlv.write_anon_struct()?;
    tlv.write_bool(0x0, false)?;
    tlv.write_bool(0x1, timed)?; // timed
    tlv.write_array(2)?;
    tlv.write_anon_struct()?;
    tlv.write_list(0)?;
    tlv.write_uint16(0, endpoint)?;
    tlv.write_uint32(1, cluster)?;
    tlv.write_uint32(2, command)?;
    tlv.write_struct_end()?;
    tlv.write_struct(1)?;
    tlv.write_raw(payload)?;
    tlv.write_struct_end()?;
    tlv.write_struct_end()?;
    tlv.write_struct_end()?;
    tlv.write_uint8(0xff, 10)?;
    tlv.write_struct_end()?;
    Ok(tlv.data)
}

pub fn im_timed_request(exchange_id: u16, timeout: u16) -> Result<Vec<u8>> {
    let b = ProtocolMessageHeader {
        exchange_flags: 5,
        opcode: ProtocolMessageHeader::INTERACTION_OPCODE_TIMED_REQ,
        exchange_id,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
        ack_counter: 0,
    }
    .encode()?;

    let mut tlv = tlv::TlvBuffer::from_vec(b);
    tlv.write_anon_struct()?;
    tlv.write_uint16(0, timeout)?;
    tlv.write_uint8(0xff, 10)?;
    tlv.write_struct_end()?;
    Ok(tlv.data)
}

pub fn im_read_request(endpoint: u16, cluster: u32, attr: u32, exchange: u16) -> Result<Vec<u8>> {
    let b = ProtocolMessageHeader {
        exchange_flags: 5,
        opcode: ProtocolMessageHeader::INTERACTION_OPCODE_READ_REQ,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
        ack_counter: 0,
    }
    .encode()?;

    let mut tlv = tlv::TlvBuffer::from_vec(b);
    tlv.write_anon_struct()?;
    tlv.write_array(0)?;
    tlv.write_anon_list()?;
    tlv.write_uint16(2, endpoint)?;
    tlv.write_uint32(3, cluster)?;
    tlv.write_uint32(4, attr)?;
    tlv.write_struct_end()?;
    tlv.write_struct_end()?;
    tlv.write_bool(3, true)?;
    tlv.write_uint8(0xff, 10)?;
    tlv.write_struct_end()?;
    Ok(tlv.data)
}

pub fn parse_im_invoke_resp(resp: &TlvItem) -> Result<(u32, u32)> {
    let common_status = resp
        .get_int(&[1, 0, 1, 1, 0])
        .context("parse_im_invoke_resp: status not found")?;
    if common_status == 0 {
        return Ok((0, 0));
    }
    let stat = resp
        .get_int(&[1, 0, 1, 1, 1])
        .context("parse_im_invoke_resp: unexpected response")?;
    Ok((common_status as u32, stat as u32))
}

#[cfg(test)]
mod tests {
    use super::Message;

    #[test]
    pub fn test_1() {
        let msg = "04000000a5a0b90d3320764c7d52ef86052060d5000015300120cabe444262d4e5dd568c755ed77e0829b9983c4d62b480b579811ec383eb69c625020837240300280418";
        let msg = hex::decode(msg).unwrap();
        let m = Message::decode(&msg).unwrap();
        println!("{:?}", m);

        let msg = "04000000000000000000000000000000012001000000153001203052998af1897150086e6c84003c074df93a796b4f68a9221ee4e40325014aaf25020100240300280418";
        let msg = hex::decode(msg).unwrap();
        let m = Message::decode(&msg).unwrap();
        println!("{:?}", m);
    }
}
