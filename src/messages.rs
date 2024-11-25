

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Result, Write};
use rand::RngCore;

use crate::tlv::{self, TlvItem};

#[derive(Debug)]
pub struct MessageHeader {
    pub flags: u8,
    pub security_flags: u8,
    pub session_id: u16,
    pub message_counter: u32,
    pub source_node_id: Vec<u8>,
    pub destination_node_id: Vec<u8>
}

impl MessageHeader {
    const FLAG_SRC_PRESENT: u8 = 4;
    const DSIZ_64: u8 = 1;
    const DSIZ_16: u8 = 2;
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut flags: u8 = 0;
        if self.source_node_id.len() == 8 {
            flags |= Self::FLAG_SRC_PRESENT;
        }
        if self.destination_node_id.len() == 2 {
            flags |= Self::DSIZ_16
        } else if self.destination_node_id.len() == 8 {
            flags |= Self::DSIZ_64
        }
        let mut out = Vec::with_capacity(1024);
        out.write_u8(flags)?;
        out.write_u16::<LittleEndian>(self.session_id)?;
        out.write_u8(self.security_flags)?;
        out.write_u32::<LittleEndian>(self.message_counter)?;
        if self.source_node_id.len() == 8 {
            out.write_all(&self.source_node_id)?;
        }
        if !self.destination_node_id.is_empty() {
            out.write_all(&self.destination_node_id)?;
        }
        Ok(out)
    }
    pub fn decode(data: &[u8]) -> Result<(Self, Vec<u8>)> {
        let mut cursor = std::io::Cursor::new(data);
        let flags = cursor.read_u8()?;
        let session_id = cursor.read_u16::<LittleEndian>()?;
        let security_flags = cursor.read_u8()?;
        let message_counter = cursor.read_u32::<LittleEndian>()?;
        let mut source_node_id = Vec::new();
        let mut destination_node_id = Vec::new();
        if (flags & Self::FLAG_SRC_PRESENT) != 0 {
            source_node_id.resize(8, 0);
            cursor.read_exact(source_node_id.as_mut())?;
        };
        if (flags & 3) != 0 {
            let dst_size = match flags & 3 {
                Self::DSIZ_64 => 8,
                Self::DSIZ_16 => 2,
                _ => 0
            };
            if dst_size > 0 {
                destination_node_id.resize(dst_size, 0);
                cursor.read_exact(destination_node_id.as_mut())?;
            };
        };
        let mut rest = Vec::new();
        cursor.read_to_end(&mut rest)?;
        Ok((Self {
            flags,
            security_flags,
            session_id,
            message_counter,
            source_node_id,
            destination_node_id
        },
        rest))
    }
}

#[derive(Debug)]
pub struct ProtocolMessageHeader {
    exchange_flags: u8,
    pub opcode: u8,
    pub exchange_id: u16,
    pub protocol_id: u16,
    pub ack_counter: u32
}

impl ProtocolMessageHeader {
    pub const FLAG_INITIATOR: u8 = 1;
    pub const FLAG_ACK: u8 = 2;
    pub const FLAG_RELIABILITY: u8 = 4;

    pub const OPCODE_ACK: u8 = 0x10;
    pub const OPCODE_PBKDF_REQ: u8 = 0x20;
    pub const OPCODE_PBKDF_RESP: u8 = 0x21;
    pub const OPCODE_PBKDF_PAKE1: u8 = 0x22;
    pub const OPCODE_PBKDF_PAKE2: u8 = 0x23;
    pub const OPCODE_PBKDF_PAKE3: u8 = 0x24;
    pub const OPCODE_STATUS: u8 = 0x40;
    

    pub const INTERACTION_OPCODE_READ_REQ :u8 = 0x2;
    pub const INTERACTION_OPCODE_INVOKE_REQ :u8 = 0x8;
    

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
        Ok((Self {
            exchange_flags,
            opcode,
            exchange_id,
            protocol_id,
            ack_counter
        },
        rest
    ))
    }
}

#[derive(Debug)]
pub struct Message {
    pub message_header: MessageHeader,
    pub protocol_header: ProtocolMessageHeader,
    pub payload: Vec<u8>,
    pub tlv: TlvItem
}

impl Message {
    pub fn decode(data: &[u8]) -> Result<Self> {
        let (message_header, rest) = MessageHeader::decode(data)?;
        let (protocol_header, rest) = ProtocolMessageHeader::decode(&rest)?;
        if (protocol_header.protocol_id == ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL)
            && (protocol_header.opcode == ProtocolMessageHeader::OPCODE_STATUS) {
                return Ok(Self {
                    message_header,
                    protocol_header,
                    payload: rest,
                    tlv: TlvItem {
                        tag: 0,
                        value: tlv::TlvItemValue::Invalid(),
                    }
                })
            }
        let tlv = tlv::decode_tlv(&rest).unwrap();
        Ok(Self {
            message_header,
            protocol_header,
            payload: rest,
            tlv
        })
    }
    /*pub fn decode2(data: &[u8]) -> Self {
        let (message_header, rest) = MessageHeader::decode(data).unwrap();
        let (protocol_header, rest) = ProtocolMessageHeader::decode(&rest).unwrap();


        let tlv = tlv::decode_tlv(&[]).unwrap();
        Self {
            message_header,
            protocol_header,
            payload: rest,
            tlv
        }
    }*/
}

pub fn ack(exchange: u16, ack: i64) -> Result<Vec<u8>> {
    let mut flags = ProtocolMessageHeader::FLAG_INITIATOR | ProtocolMessageHeader::FLAG_RELIABILITY;
    flags |= ProtocolMessageHeader::FLAG_ACK;
    let prot = ProtocolMessageHeader {
        exchange_flags: flags,
        opcode: ProtocolMessageHeader::OPCODE_ACK,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
        ack_counter: ack as u32
    };
    prot.encode()
}

pub fn pbkdf_req(exchange: u16) -> Result<Vec<u8>> {
    let prot = ProtocolMessageHeader {
        exchange_flags: ProtocolMessageHeader::FLAG_INITIATOR | ProtocolMessageHeader::FLAG_RELIABILITY,
        opcode: ProtocolMessageHeader::OPCODE_PBKDF_REQ,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
        ack_counter: 0
    };
    let mut b = prot.encode()?;
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
    let prot = ProtocolMessageHeader {
        exchange_flags: flags,
        opcode: ProtocolMessageHeader::OPCODE_PBKDF_PAKE1,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
        ack_counter: ack as u32
    };
    let mut b = prot.encode()?;
    let mut tlv = tlv::TlvBuffer::new();
    tlv.write_anon_struct()?;
    tlv.write_octetstring(0x1, key)?;
    tlv.write_struct_end()?;

    b.write_all(&tlv.data)?;
    Ok(b)
}


pub fn pake3(exchange: u16, key: &[u8], ack: i64) -> Result<Vec<u8>> {
    let mut flags = 0x5;
    if ack >= 0 {
        flags |= 2
    }
    let prot = ProtocolMessageHeader {
        exchange_flags: flags,
        opcode: ProtocolMessageHeader::OPCODE_PBKDF_PAKE3,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
        ack_counter: ack as u32
    };
    let mut b = prot.encode()?;
    let mut tlv = tlv::TlvBuffer::new();
    tlv.write_anon_struct()?;
    tlv.write_octetstring(0x1, key)?;
    tlv.write_struct_end()?;

    b.write_all(&tlv.data)?;
    Ok(b)
}

pub fn sigma1(exchange: u16, payload: &[u8]) -> Result<Vec<u8>> {

    let prot = ProtocolMessageHeader {
        exchange_flags: 5,
        opcode: 0x30,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
        ack_counter: 0
    };
    let mut b = prot.encode()?;
    b.write_all(payload)?;
    Ok(b)
}
pub fn sigma3(exchange: u16, payload: &[u8]) -> Result<Vec<u8>> {

    let prot = ProtocolMessageHeader {
        exchange_flags: 5,
        opcode: 0x32,
        exchange_id: exchange,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
        ack_counter: 0
    };
    let mut b = prot.encode()?;
    b.write_all(payload)?;
    Ok(b)
}


pub fn im_invoke_request(endpoint: u16, cluster: u32, command: u32, exchange_id: u16, payload: &[u8], timed: bool) -> Result<Vec<u8>> {
    let flags = 5;
    let prot = ProtocolMessageHeader {
        exchange_flags: flags,
        opcode: ProtocolMessageHeader::INTERACTION_OPCODE_INVOKE_REQ,
        exchange_id,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
        ack_counter: 0
    };

    let mut b = prot.encode()?;
    let mut tlv = tlv::TlvBuffer::new();
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
    b.write_all(&tlv.data)?;
    Ok(b)
}

pub fn im_read_request(endpoint: u16, cluster: u32, attr: u32) -> Result<Vec<u8>> {
    let flags = 5;
    let prot = ProtocolMessageHeader {
        exchange_flags: flags,
        opcode: ProtocolMessageHeader::INTERACTION_OPCODE_READ_REQ,
        exchange_id: 0,
        protocol_id: ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
        ack_counter: 0
    };

    let mut b = prot.encode()?;
    let mut tlv = tlv::TlvBuffer::new();
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

    b.write_all(&tlv.data)?;
    Ok(b)
}