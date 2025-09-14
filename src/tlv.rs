//! Utilities to decode/encode matter tlv

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use core::fmt;
use std::io::{Cursor, Read, Result, Write};

/// Buffer to encode matter tlv. Create buffer, write elements then use data member which contains encoded tlv.
/// Example how to commission device using certificates pre-created in pem directory:
/// ```
/// # use matc::tlv;
/// # use anyhow::Result;
/// # fn main() -> Result<()> {
/// let mut tlv = tlv::TlvBuffer::new();
/// tlv.write_struct(1)?;
/// tlv.write_uint8(0, 100)?;
/// tlv.write_string(0, "test")?;
/// tlv.write_struct_end()?;
/// // now tlv.data contains encoded tlv buffer
/// # Ok(())
/// # }
/// ```
pub struct TlvBuffer {
    pub data: Vec<u8>,
}

const TYPE_INT_1: u8 = 0;
const TYPE_INT_2: u8 = 1;
const TYPE_INT_4: u8 = 2;
const TYPE_UINT_1: u8 = 4;
const TYPE_UINT_2: u8 = 5;
const TYPE_UINT_4: u8 = 6;
const TYPE_UINT_8: u8 = 7;
const TYPE_BOOL_FALSE: u8 = 8;
const TYPE_BOOL_TRUE: u8 = 9;
const TYPE_UTF8_L1: u8 = 0xC;
const TYPE_OCTET_STRING_L1: u8 = 0x10;
const TYPE_OCTET_STRING_L2: u8 = 0x11;

const TYPE_STRUCT: u8 = 0x15;
const TYPE_ARRAY: u8 = 0x16;
const TYPE_LIST: u8 = 0x17;
const TYPE_END_CONTAINER: u8 = 0x18;

const CTRL_CTX_L1: u8 = 1 << 5;

impl TlvBuffer {
    pub fn new() -> Self {
        Self {
            data: Vec::with_capacity(1024),
        }
    }
    pub fn from_vec(v: Vec<u8>) -> Self {
        Self { data: v }
    }
    pub fn write_raw(&mut self, data: &[u8]) -> Result<()> {
        self.data.write_all(data)
    }
    pub fn write_anon_struct(&mut self) -> Result<()> {
        self.data.write_u8(TYPE_STRUCT)?;
        Ok(())
    }
    pub fn write_anon_list(&mut self) -> Result<()> {
        self.data.write_u8(TYPE_LIST)?;
        Ok(())
    }
    pub fn write_struct(&mut self, tag: u8) -> Result<()> {
        self.data.write_u8(CTRL_CTX_L1 | TYPE_STRUCT)?;
        self.data.write_u8(tag)?;
        Ok(())
    }
    pub fn write_array(&mut self, tag: u8) -> Result<()> {
        self.data.write_u8(CTRL_CTX_L1 | TYPE_ARRAY)?;
        self.data.write_u8(tag)?;
        Ok(())
    }
    pub fn write_list(&mut self, tag: u8) -> Result<()> {
        self.data.write_u8(CTRL_CTX_L1 | TYPE_LIST)?;
        self.data.write_u8(tag)?;
        Ok(())
    }
    pub fn write_struct_end(&mut self) -> Result<()> {
        self.data.write_u8(TYPE_END_CONTAINER)?;
        Ok(())
    }
    pub fn write_string(&mut self, tag: u8, data: &str) -> Result<()> {
        let ctrl = CTRL_CTX_L1 | TYPE_UTF8_L1;
        let bytes = data.as_bytes();
        self.data.write_u8(ctrl)?;
        self.data.write_u8(tag)?;
        self.data.write_u8(bytes.len() as u8)?;
        self.data.write_all(bytes)?;
        Ok(())
    }
    pub fn write_octetstring(&mut self, tag: u8, data: &[u8]) -> Result<()> {
        if data.len() > 0xff {
            self.data.write_u8(CTRL_CTX_L1 | TYPE_OCTET_STRING_L2)?;
            self.data.write_u8(tag)?;
            self.data.write_u16::<LittleEndian>(data.len() as u16)?;
        } else {
            self.data.write_u8(CTRL_CTX_L1 | TYPE_OCTET_STRING_L1)?;
            self.data.write_u8(tag)?;
            self.data.write_u8(data.len() as u8)?;
        }
        self.data.write_all(data)?;
        Ok(())
    }
    pub fn write_int8(&mut self, tag: u8, value: i8) -> Result<()> {
        self.data.write_u8(CTRL_CTX_L1 | TYPE_INT_1)?;
        self.data.write_u8(tag)?;
        self.data.write_i8(value)
    }
    pub fn write_int16(&mut self, tag: u8, value: i16) -> Result<()> {
        self.data.write_u8(CTRL_CTX_L1 | TYPE_INT_2)?;
        self.data.write_u8(tag)?;
        self.data.write_i16::<LittleEndian>(value)
    }
    pub fn write_uint8(&mut self, tag: u8, value: u8) -> Result<()> {
        self.data.write_u8(CTRL_CTX_L1 | TYPE_UINT_1)?;
        self.data.write_u8(tag)?;
        self.data.write_u8(value)
    }
    pub fn write_uint8_notag(&mut self, value: u8) -> Result<()> {
        self.data.write_u8(TYPE_UINT_1)?;
        self.data.write_u8(value)
    }
    pub fn write_uint16(&mut self, tag: u8, value: u16) -> Result<()> {
        self.data.write_u8(CTRL_CTX_L1 | TYPE_UINT_2)?;
        self.data.write_u8(tag)?;
        self.data.write_u16::<LittleEndian>(value)
    }
    pub fn write_uint32(&mut self, tag: u8, value: u32) -> Result<()> {
        self.data.write_u8(CTRL_CTX_L1 | TYPE_UINT_4)?;
        self.data.write_u8(tag)?;
        self.data.write_u32::<LittleEndian>(value)
    }
    pub fn write_uint64(&mut self, tag: u8, value: u64) -> Result<()> {
        self.data.write_u8(CTRL_CTX_L1 | TYPE_UINT_8)?;
        self.data.write_u8(tag)?;
        self.data.write_u64::<LittleEndian>(value)
    }
    pub fn write_bool(&mut self, tag: u8, value: bool) -> Result<()> {
        if value {
            self.data.write_u8(CTRL_CTX_L1 | TYPE_BOOL_TRUE)?;
        } else {
            self.data.write_u8(CTRL_CTX_L1 | TYPE_BOOL_FALSE)?;
        }
        self.data.write_u8(tag)
    }
}

impl Default for TlvBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Enum containing data of decoded tlv element
#[derive(Clone, PartialEq)]
pub enum TlvItemValue {
    Int(u64),
    Bool(bool),
    String(String),
    OctetString(Vec<u8>),
    List(Vec<TlvItem>),
    Nil(),
    Invalid(),
}

impl From<TlvItemValue> for bool {
    fn from(value: TlvItemValue) -> Self {
        match value {
            TlvItemValue::Bool(b) => b,
            _ => false,
        }
    }
}
impl From<TlvItemValue> for String {
    fn from(value: TlvItemValue) -> Self {
        match value {
            TlvItemValue::String(s) => s,
            _ => String::new(),
        }
    }
}

impl<'a> TryFrom<&'a TlvItemValue> for &'a [u8] {
    type Error = &'static str;
    fn try_from(value: &'a TlvItemValue) -> std::result::Result<Self, Self::Error> {
        if let TlvItemValue::OctetString(ref s) = value {
            Ok(s.as_slice())
        } else {
            Err("Not an octet string")
        }
    }
}
impl From<TlvItemValue> for Vec<u8> {
    fn from(value: TlvItemValue) -> Self {
        match value {
            TlvItemValue::OctetString(s) => s,
            _ => Vec::new(),
        }
    }
}
impl From<TlvItemValue> for u64 {
    fn from(value: TlvItemValue) -> Self {
        match value {
            TlvItemValue::Int(i) => i,
            _ => 0,
        }
    }
}
impl From<TlvItemValue> for Vec<TlvItem> {
    fn from(value: TlvItemValue) -> Self {
        match value {
            TlvItemValue::List(lst) => lst,
            _ => panic!("Cannot convert to Vec<TlvItem>"),
        }
    }
}

/// Decoded tlv element returned by [decode_tlv]
#[derive(Debug, Clone, PartialEq)]
pub struct TlvItem {
    pub tag: u8,
    pub value: TlvItemValue,
}

impl fmt::Debug for TlvItemValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Int(arg0) => f.debug_tuple("Int").field(arg0).finish(),
            Self::Bool(arg0) => f.debug_tuple("Bool").field(arg0).finish(),
            Self::String(arg0) => f.debug_tuple("String").field(arg0).finish(),
            Self::OctetString(arg0) => f
                .debug_tuple("OctetString")
                .field(&hex::encode(arg0))
                .finish(),
            Self::List(arg0) => f.debug_tuple("List").field(arg0).finish(),
            Self::Nil() => f.debug_tuple("Nil").finish(),
            Self::Invalid() => f.debug_tuple("Invalid").finish(),
        }
    }
}

impl TlvItem {
    pub fn get(&self, tag: &[u8]) -> Option<&TlvItemValue> {
        if !tag.is_empty() {
            if let TlvItemValue::List(lst) = &self.value {
                for l in lst {
                    if l.tag == tag[0] {
                        return l.get(&tag[1..]);
                    };
                }
            }
            None
        } else {
            Some(&self.value)
        }
    }
    pub fn get_item(&self, tag: &[u8]) -> Option<&TlvItem> {
        if !tag.is_empty() {
            if let TlvItemValue::List(lst) = &self.value {
                for l in lst {
                    if l.tag == tag[0] {
                        return l.get_item(&tag[1..]);
                    };
                }
            }
            None
        } else {
            Some(self)
        }
    }
    pub fn get_int(&self, tag: &[u8]) -> Option<u64> {
        let found = self.get(tag);
        if let Some(TlvItemValue::Int(i)) = found {
            Some(*i)
        } else {
            None
        }
    }
    pub fn get_t<T>(&self, tag: &[u8]) -> Option<T>
    where
        T: From<TlvItemValue>,
    {
        self.get(tag).map(|f| f.clone().into())
    }

    pub fn get_bool(&self, tag: &[u8]) -> Option<bool> {
        self.get(tag).map(|f| f.clone().into())
        /*let found = self.get(tag);
        if let Some(TlvItemValue::Bool(i)) = found {
            Some(*i)
        } else {
            None
        }*/
    }
    pub fn get_u8(&self, tag: &[u8]) -> Option<u8> {
        let found = self.get(tag);
        if let Some(TlvItemValue::Int(i)) = found {
            Some(*i as u8)
        } else {
            None
        }
    }
    pub fn get_u16(&self, tag: &[u8]) -> Option<u16> {
        let found = self.get(tag);
        if let Some(TlvItemValue::Int(i)) = found {
            Some(*i as u16)
        } else {
            None
        }
    }
    pub fn get_u32(&self, tag: &[u8]) -> Option<u32> {
        let found = self.get(tag);
        if let Some(TlvItemValue::Int(i)) = found {
            Some(*i as u32)
        } else {
            None
        }
    }
    pub fn get_u64(&self, tag: &[u8]) -> Option<u64> {
        let found = self.get(tag);
        if let Some(TlvItemValue::Int(i)) = found {
            Some(*i)
        } else {
            None
        }
    }
    pub fn get_octet_string(&self, tag: &[u8]) -> Option<&[u8]> {
        let found = self.get(tag);
        if let Some(TlvItemValue::OctetString(o)) = found {
            Some(o)
        } else {
            None
        }
    }
    pub fn get_octet_string_owned(&self, tag: &[u8]) -> Option<Vec<u8>> {
        let found = self.get(tag);
        if let Some(TlvItemValue::OctetString(o)) = found {
            Some(o.to_owned())
        } else {
            None
        }
    }
    pub fn get_string_owned(&self, tag: &[u8]) -> Option<String> {
        let found = self.get(tag);
        if let Some(TlvItemValue::String(o)) = found {
            Some(o.clone())
        } else {
            None
        }
    }
    pub fn dump(&self, indent: usize) {
        match &self.value {
            TlvItemValue::List(vec) => {
                println!("{} {}", " ".to_owned().repeat(indent), self.tag);
                for v in vec {
                    v.dump(indent + 1);
                }
            }
            _ => {
                println!(
                    "{} {} {:?}",
                    " ".to_owned().repeat(indent),
                    self.tag,
                    self.value
                );
            }
        }
    }
}

fn read_tag(tagctrl: u8, cursor: &mut Cursor<&[u8]>) -> Result<u8> {
    if tagctrl == 1 {
        cursor.read_u8()
    } else {
        Ok(0)
    }
}

fn decode(cursor: &mut Cursor<&[u8]>, container: &mut Vec<TlvItem>) -> Result<()> {
    while cursor.position() < cursor.get_ref().len() as u64 {
        let fb = cursor.read_u8()?;
        let tp = fb & 0x1f;
        let tagctrl = fb >> 5;
        let tag = read_tag(tagctrl, cursor)?;
        match tp {
            TYPE_INT_1 => {
                let value = cursor.read_u8()?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Int(value as u64),
                };
                container.push(item);
            }
            TYPE_INT_4 => {
                let value = cursor.read_i32::<LittleEndian>()?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Int(value as u64),
                };
                container.push(item);
            }
            TYPE_UINT_1 => {
                let value = cursor.read_u8()?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Int(value as u64),
                };
                container.push(item);
            }
            TYPE_UINT_2 => {
                let value = cursor.read_u16::<LittleEndian>()?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Int(value as u64),
                };
                container.push(item);
            }
            TYPE_UINT_4 => {
                let value = cursor.read_u32::<LittleEndian>()?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Int(value as u64),
                };
                container.push(item);
            }
            TYPE_UINT_8 => {
                let value = cursor.read_u64::<LittleEndian>()?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Int(value),
                };
                container.push(item);
            }
            TYPE_BOOL_FALSE => {
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Bool(false),
                };
                container.push(item);
            }
            TYPE_BOOL_TRUE => {
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Bool(true),
                };
                container.push(item);
            }
            TYPE_UTF8_L1 => {
                // utf8 string
                let size = cursor.read_u8()?;
                let mut value = vec![0; size as usize];
                cursor.read_exact(&mut value)?;
                let str = String::from_utf8(value);
                let typ = match str {
                    Ok(s) => TlvItemValue::String(s),
                    Err(_) => TlvItemValue::Invalid(),
                };
                let item = TlvItem { tag, value: typ };
                container.push(item);
            }
            TYPE_OCTET_STRING_L1 => {
                // octet string
                let size = cursor.read_u8()?;
                let mut value = vec![0; size as usize];
                cursor.read_exact(&mut value)?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::OctetString(value),
                };
                container.push(item);
            }
            TYPE_OCTET_STRING_L2 => {
                // octet string large
                let size = cursor.read_u16::<LittleEndian>()?;
                let mut value = vec![0; size as usize];
                cursor.read_exact(&mut value)?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::OctetString(value),
                };
                container.push(item);
            }
            TYPE_STRUCT => {
                //list
                let mut c2 = Vec::new();
                decode(cursor, &mut c2)?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::List(c2),
                };
                container.push(item);
            }
            TYPE_ARRAY => {
                //list
                let mut c2 = Vec::new();
                decode(cursor, &mut c2)?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::List(c2),
                };
                container.push(item);
            }
            TYPE_LIST => {
                //list
                let mut c2 = Vec::new();
                decode(cursor, &mut c2)?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::List(c2),
                };
                container.push(item);
            }
            TYPE_END_CONTAINER => return Ok(()),
            0x14 => {
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Nil(),
                };
                container.push(item);
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown tlv type 0x{:x}", tp),
                ))
            }
        }
    }
    Ok(())
}

/// decode raw buffer with tlv data
pub fn decode_tlv(data: &[u8]) -> Result<TlvItem> {
    let mut container = Vec::new();
    let mut cursor = std::io::Cursor::new(data);
    decode(&mut cursor, &mut container)?;
    if container.len() == 1 {
        if let Some(i) = container.pop() {
            Ok(i)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no data found",
            ))
        }
    } else {
        Ok(TlvItem {
            tag: 0,
            value: TlvItemValue::List(container),
        })
    }
}

#[derive(Debug)]
pub enum TlvItemValueEnc {
    Int8(i8),
    Int16(i16),
    UInt8(u8),
    UInt16(u16),
    UInt32(u32),
    UInt64(u64),
    Bool(bool),
    String(String),
    OctetString(Vec<u8>),
    StructAnon(Vec<TlvItemEnc>),
    StructInvisible(Vec<TlvItemEnc>),
    Invalid(),
}

/// Structure used for document style encoding.
///
/// ```
/// # use matc::tlv;
/// let t1 = tlv::TlvItemEnc {
///   tag: 0,
///   value: tlv::TlvItemValueEnc::StructAnon(vec![
///     tlv::TlvItemEnc { tag: 0, value: tlv::TlvItemValueEnc::UInt8(6) },
///     tlv::TlvItemEnc { tag: 1, value: tlv::TlvItemValueEnc::UInt8(7) }
///   ]),
/// };
/// let o = t1.encode().unwrap();
/// ```
#[derive(Debug)]
pub struct TlvItemEnc {
    pub tag: u8,
    pub value: TlvItemValueEnc,
}

impl From<(u8, TlvItemValueEnc)> for TlvItemEnc {
    fn from(item: (u8, TlvItemValueEnc)) -> Self {
        TlvItemEnc {
            tag: item.0,
            value: item.1,
        }
    }
}

impl TlvItemEnc {
    fn encode_internal(&self, buf: &mut TlvBuffer) -> Result<()> {
        match &self.value {
            TlvItemValueEnc::Int8(i) => {
                buf.write_int8(self.tag, *i)?;
            }
            TlvItemValueEnc::Int16(i) => {
                buf.write_int16(self.tag, *i)?;
            }
            TlvItemValueEnc::UInt8(i) => {
                buf.write_uint8(self.tag, *i)?;
            }
            TlvItemValueEnc::UInt16(i) => {
                buf.write_uint16(self.tag, *i)?;
            }
            TlvItemValueEnc::UInt32(i) => {
                buf.write_uint32(self.tag, *i)?;
            }
            TlvItemValueEnc::UInt64(i) => {
                buf.write_uint64(self.tag, *i)?;
            }
            TlvItemValueEnc::Bool(v) => {
                buf.write_bool(self.tag, *v)?;
            }
            TlvItemValueEnc::String(s) => {
                buf.write_string(self.tag, s)?;
            }
            TlvItemValueEnc::OctetString(vec) => {
                buf.write_octetstring(self.tag, vec)?;
            }
            TlvItemValueEnc::StructAnon(vec) => {
                buf.write_anon_struct()?;
                for i in vec {
                    i.encode_internal(buf)?;
                }
                buf.write_struct_end()?;
            }
            TlvItemValueEnc::StructInvisible(vec) => {
                for i in vec {
                    i.encode_internal(buf)?;
                }
            }
            TlvItemValueEnc::Invalid() => todo!(),
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut tlv = TlvBuffer::new();
        self.encode_internal(&mut tlv)?;
        Ok(tlv.data)
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_tlv, TlvBuffer, TlvItemEnc, TlvItemValue, TlvItemValueEnc};

    #[test]
    fn test_1() {
        let t1 = TlvItemEnc {
            tag: 0,
            value: TlvItemValueEnc::StructAnon(vec![
                TlvItemEnc {
                    tag: 0,
                    value: TlvItemValueEnc::UInt8(6),
                },
                TlvItemEnc {
                    tag: 1,
                    value: TlvItemValueEnc::UInt8(7),
                },
            ]),
        };
        let o = t1.encode().unwrap();
        assert_eq!(hex::encode(o), "1524000624010718");

        let mut tlv = TlvBuffer::new();
        tlv.write_anon_struct().unwrap();
        tlv.write_octetstring(0x1, &[1, 2, 3]).unwrap();
        tlv.write_struct_end().unwrap();
        assert_eq!(hex::encode(tlv.data), "1530010301020318");

        let t1 = TlvItemEnc {
            tag: 0,
            value: TlvItemValueEnc::StructAnon(vec![TlvItemEnc {
                tag: 1,
                value: TlvItemValueEnc::OctetString(vec![1, 2, 3]),
            }]),
        }
        .encode()
        .unwrap();
        assert_eq!(hex::encode(t1), "1530010301020318");
    }

    #[test]
    fn test_decode_integers() {
        // Test uint8
        let mut tlv = TlvBuffer::new();
        tlv.write_uint8(1, 42).unwrap();
        let decoded = decode_tlv(&tlv.data).unwrap();
        assert_eq!(decoded.get_u8(&[]), Some(42));

        // Test uint16
        let mut tlv = TlvBuffer::new();
        tlv.write_uint16(2, 1000).unwrap();
        let decoded = decode_tlv(&tlv.data).unwrap();
        assert_eq!(decoded.get_u16(&[]), Some(1000));

        // Test uint32
        let mut tlv = TlvBuffer::new();
        tlv.write_uint32(3, 100000).unwrap();
        let decoded = decode_tlv(&tlv.data).unwrap();
        assert_eq!(decoded.get_u32(&[]), Some(100000));

        // Test uint64
        let mut tlv = TlvBuffer::new();
        tlv.write_uint64(4, 1000000000000).unwrap();
        let decoded = decode_tlv(&tlv.data).unwrap();
        assert_eq!(decoded.get_u64(&[]), Some(1000000000000));
    }

    #[test]
    fn test_decode_booleans() {
        // Test true
        let mut tlv = TlvBuffer::new();
        tlv.write_bool(1, true).unwrap();
        let decoded = decode_tlv(&tlv.data).unwrap();
        assert_eq!(decoded.get_bool(&[]), Some(true));

        // Test false
        let mut tlv = TlvBuffer::new();
        tlv.write_bool(2, false).unwrap();
        let decoded = decode_tlv(&tlv.data).unwrap();
        assert_eq!(decoded.get_bool(&[]), Some(false));
        assert_eq!(decoded.get_t(&[]), Some(false));
    }

    #[test]
    fn test_decode_strings() {
        let mut tlv = TlvBuffer::new();
        tlv.write_string(1, "hello world").unwrap();
        let decoded = decode_tlv(&tlv.data).unwrap();
        assert_eq!(
            decoded.get_string_owned(&[]),
            Some("hello world".to_string())
        );
        assert_eq!(decoded.get_t(&[]), Some("hello world".to_string()));
    }

    #[test]
    fn test_decode_octet_strings() {
        // Test small octet string (L1)
        let mut tlv = TlvBuffer::new();
        let data = vec![1, 2, 3, 4, 5];
        tlv.write_octetstring(1, &data).unwrap();
        let decoded = decode_tlv(&tlv.data).unwrap();
        assert_eq!(decoded.get_octet_string(&[]), Some(data.as_slice()));

        // Test large octet string (L2)
        let mut tlv = TlvBuffer::new();
        let large_data = vec![0; 300]; // Larger than 255 bytes
        tlv.write_octetstring(2, &large_data).unwrap();
        let decoded = decode_tlv(&tlv.data).unwrap();
        assert_eq!(decoded.get_octet_string(&[]), Some(large_data.as_slice()));
        assert_eq!(
            decoded.get_octet_string_owned(&[]),
            Some(large_data.clone())
        );
    }

    #[test]
    fn test_decode_structures() {
        let mut tlv = TlvBuffer::new();
        tlv.write_struct(1).unwrap();
        tlv.write_uint8(0, 100).unwrap();
        tlv.write_string(1, "test").unwrap();
        tlv.write_bool(2, true).unwrap();
        tlv.write_struct_end().unwrap();

        let decoded = decode_tlv(&tlv.data).unwrap();

        // Test nested access
        assert_eq!(decoded.get_u8(&[0]), Some(100));
        assert_eq!(decoded.get_string_owned(&[1]), Some("test".to_string()));
        assert_eq!(decoded.get_bool(&[2]), Some(true));

        // Verify it's a list structure
        if let TlvItemValue::List(items) = &decoded.value {
            assert_eq!(items.len(), 3);
        }
    }

    #[test]
    fn test_decode_anonymous_structures() {
        let mut tlv = TlvBuffer::new();
        tlv.write_anon_struct().unwrap();
        tlv.write_uint8_notag(42).unwrap();
        tlv.write_uint8_notag(84).unwrap();
        tlv.write_struct_end().unwrap();

        let decoded = decode_tlv(&tlv.data).unwrap();

        if let TlvItemValue::List(items) = &decoded.value {
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].tag, 0);
            assert_eq!(items[1].tag, 0);
        }
    }

    #[test]
    fn test_decode_arrays_and_lists() {
        // Test array
        let mut tlv = TlvBuffer::new();
        tlv.write_array(1).unwrap();
        tlv.write_uint8(0, 1).unwrap();
        tlv.write_uint8(0, 2).unwrap();
        tlv.write_uint8(0, 3).unwrap();
        tlv.write_struct_end().unwrap();

        let decoded = decode_tlv(&tlv.data).unwrap();
        if let Some(TlvItemValue::List(items)) = decoded.get(&[]) {
            assert_eq!(items.len(), 3);
            assert_eq!(items[0].get_u8(&[]), Some(1));
            assert_eq!(items[1].get_u8(&[]), Some(2));
            assert_eq!(items[2].get_u8(&[]), Some(3));
        } else {
            panic!("Expected array structure");
        }

        // Test list
        let mut tlv = TlvBuffer::new();
        tlv.write_list(2).unwrap();
        tlv.write_string(0, "item1").unwrap();
        tlv.write_string(1, "item2").unwrap();
        tlv.write_struct_end().unwrap();

        let decoded = decode_tlv(&tlv.data).unwrap();
        if let Some(TlvItemValue::List(items)) = decoded.get(&[]) {
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].get_string_owned(&[]), Some("item1".to_string()));
            assert_eq!(items[1].get_string_owned(&[]), Some("item2".to_string()));
        } else {
            panic!("Expected list structure");
        }
    }

    #[test]
    fn test_decode_mixed_container() {
        let mut tlv = TlvBuffer::new();
        tlv.write_uint8(0, 255).unwrap();
        tlv.write_string(1, "mixed").unwrap();
        tlv.write_bool(2, false).unwrap();

        let decoded = decode_tlv(&tlv.data).unwrap();

        // Should create a list with multiple items
        if let TlvItemValue::List(items) = &decoded.value {
            assert_eq!(items.len(), 3);
            assert_eq!(items[0].get_u8(&[]), Some(255));
            assert_eq!(items[1].get_string_owned(&[]), Some("mixed".to_string()));
            assert_eq!(items[2].get_bool(&[]), Some(false));
        } else {
            panic!("Expected list of items");
        }
    }

    #[test]
    fn test_decode_nested_structures() {
        let mut tlv = TlvBuffer::new();
        tlv.write_struct(1).unwrap();
        tlv.write_struct(2).unwrap();
        tlv.write_uint8(3, 42).unwrap();
        tlv.write_struct_end().unwrap(); // End inner struct
        tlv.write_string(4, "outer").unwrap();
        tlv.write_struct_end().unwrap(); // End outer struct

        let decoded = decode_tlv(&tlv.data).unwrap();

        // Test deep nested access
        assert_eq!(decoded.get_u8(&[2, 3]), Some(42));
        assert_eq!(decoded.get_string_owned(&[4]), Some("outer".to_string()));
    }

    #[test]
    fn test_decode_getter_methods() {
        let mut tlv = TlvBuffer::new();
        tlv.write_struct(0).unwrap();
        tlv.write_uint64(1, 0xFFFFFFFFFFFFFFFF).unwrap();
        tlv.write_uint32(2, 0xFFFFFFFF).unwrap();
        tlv.write_uint16(3, 0xFFFF).unwrap();
        tlv.write_uint8(4, 0xFF).unwrap();
        tlv.write_struct_end().unwrap();

        let decoded = decode_tlv(&tlv.data).unwrap();

        // Test type conversions
        assert_eq!(decoded.get_u64(&[1]), Some(0xFFFFFFFFFFFFFFFF));
        assert_eq!(decoded.get_u32(&[2]), Some(0xFFFFFFFF));
        assert_eq!(decoded.get_u16(&[3]), Some(0xFFFF));
        assert_eq!(decoded.get_u8(&[4]), Some(0xFF));

        // Test downcasting
        assert_eq!(decoded.get_u8(&[1]), Some(0xFF)); // u64 -> u8
        assert_eq!(decoded.get_u16(&[1]), Some(0xFFFF)); // u64 -> u16
    }

    #[test]
    fn test_decode_invalid_access() {
        let mut tlv = TlvBuffer::new();
        tlv.write_uint8(1, 42).unwrap();
        let decoded = decode_tlv(&tlv.data).unwrap();

        // Test accessing non-existent tags
        assert_eq!(decoded.get_u8(&[99]), None);
        assert_eq!(decoded.get_string_owned(&[1]), None); // Wrong type
        assert_eq!(decoded.get_bool(&[1]), None); // Wrong type
    }

    #[test]
    fn test_decode_empty_structure() {
        let mut tlv = TlvBuffer::new();
        tlv.write_anon_struct().unwrap();
        tlv.write_struct_end().unwrap();

        let decoded = decode_tlv(&tlv.data).unwrap();

        if let TlvItemValue::List(items) = &decoded.value {
            assert_eq!(items.len(), 0);
        } else {
            panic!("Expected empty list");
        }
    }

    #[test]
    fn test_get_item_method() {
        let mut tlv = TlvBuffer::new();
        tlv.write_struct(1).unwrap();
        tlv.write_uint8(2, 100).unwrap();
        tlv.write_string(3, "test").unwrap();
        tlv.write_bool(4, true).unwrap();
        tlv.write_struct(5).unwrap();
        tlv.write_string(1, "inner").unwrap();
        tlv.write_struct_end().unwrap();
        tlv.write_struct_end().unwrap();

        let decoded = decode_tlv(&tlv.data).unwrap();

        // Test get_item returns the actual item
        let item = decoded.get_item(&[2]).unwrap();
        assert_eq!(item.tag, 2);
        if let TlvItemValue::Int(val) = &item.value {
            assert_eq!(*val, 100);
        } else {
            panic!("Expected Int value");
        }
        let item = decoded.get_item(&[3]).unwrap();
        assert_eq!(item.tag, 3);
        if let TlvItemValue::String(val) = &item.value {
            assert_eq!(*val, "test");
        } else {
            panic!("Expected String value");
        }
        let item = decoded.get_item(&[4]).unwrap();
        assert_eq!(item.tag, 4);
        if let TlvItemValue::Bool(val) = &item.value {
            assert!(*val);
        } else {
            panic!("Expected Bool value");
        }
        let item = decoded.get_item(&[5]).unwrap();
        assert_eq!(item.tag, 5);
        if let TlvItemValue::List(items) = &item.value {
            assert_eq!(items.len(), 1);
            let inner_item = &items[0];
            assert_eq!(inner_item.tag, 1);
            if let TlvItemValue::String(val) = &inner_item.value {
                assert_eq!(*val, "inner");
            } else {
                panic!("Expected String value");
            }
        } else {
            panic!("Expected List value");
        }
        let item = decoded.get_item(&[99]);
        assert!(item.is_none());
    }
}
