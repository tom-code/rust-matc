use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Result, Write};

pub struct TlvBuffer {
    pub data: Vec<u8>,
}

const TYPE_INT_1: u8 = 0;
const TYPE_UINT_1: u8 = 4;
const TYPE_UINT_2: u8 = 5;
const TYPE_UINT_4: u8 = 6;
const TYPE_UINT_8: u8 = 7;
const TYPE_BOOL_FALSE: u8 = 8;
const TYPE_BOOL_TRUE: u8 = 9;

const TYPE_OCTET_STRING_L1: u8 = 0x10;
const TYPE_OCTET_STRING_L2: u8 = 0x11;

impl TlvBuffer {
    pub fn new() -> Self {
        Self {
            data: Vec::with_capacity(1024),
        }
    }
    pub fn write_raw(&mut self, data: &[u8]) -> Result<()> {
        self.data.write_all(data)
    }
    pub fn write_anon_struct(&mut self) -> Result<()> {
        self.data.write_u8(0x15)?;
        Ok(())
    }
    pub fn write_anon_list(&mut self) -> Result<()> {
        self.data.write_u8(0x17)?;
        Ok(())
    }
    pub fn write_struct(&mut self, tag: u8) -> Result<()> {
        self.data.write_u8(0x35)?;
        self.data.write_u8(tag)?;
        Ok(())
    }
    pub fn write_array(&mut self, tag: u8) -> Result<()> {
        self.data.write_u8(0x36)?;
        self.data.write_u8(tag)?;
        Ok(())
    }
    pub fn write_list(&mut self, tag: u8) -> Result<()> {
        self.data.write_u8(0x37)?;
        self.data.write_u8(tag)?;
        Ok(())
    }
    pub fn write_struct_end(&mut self) -> Result<()> {
        self.data.write_u8(0x18)?;
        Ok(())
    }
    pub fn write_octetstring(&mut self, tag: u8, data: &[u8]) -> Result<()> {
        let mut ctrl: u8 = 1 << 5;
        if data.len() > 0xff {
            ctrl |= TYPE_OCTET_STRING_L2;
            self.data.write_u8(ctrl)?;
            self.data.write_u8(tag)?;
            self.data.write_u16::<LittleEndian>(data.len() as u16)?;
        } else {
            ctrl |= TYPE_OCTET_STRING_L1;
            self.data.write_u8(ctrl)?;
            self.data.write_u8(tag)?;
            self.data.write_u8(data.len() as u8)?;
        }
        self.data.write_all(data)?;
        Ok(())
    }
    pub fn write_int8(&mut self, tag: u8, value: i8) -> Result<()> {
        self.data.write_u8((1 << 5) | TYPE_INT_1)?;
        self.data.write_u8(tag)?;
        self.data.write_i8(value)
    }
    pub fn write_uint8(&mut self, tag: u8, value: u8) -> Result<()> {
        self.data.write_u8((1 << 5) | TYPE_UINT_1)?;
        self.data.write_u8(tag)?;
        self.data.write_u8(value)
    }
    pub fn write_uint16(&mut self, tag: u8, value: u16) -> Result<()> {
        self.data.write_u8((1 << 5) | TYPE_UINT_2)?;
        self.data.write_u8(tag)?;
        self.data.write_u16::<LittleEndian>(value)
    }
    pub fn write_uint32(&mut self, tag: u8, value: u32) -> Result<()> {
        self.data.write_u8((1 << 5) | TYPE_UINT_4)?;
        self.data.write_u8(tag)?;
        self.data.write_u32::<LittleEndian>(value)
    }
    pub fn write_uint64(&mut self, tag: u8, value: u64) -> Result<()> {
        self.data.write_u8((1 << 5) | TYPE_UINT_8)?;
        self.data.write_u8(tag)?;
        self.data.write_u64::<LittleEndian>(value)
    }
    pub fn write_bool(&mut self, tag: u8, value: bool) -> Result<()> {
        if value {
            self.data.write_u8((1 << 5) | TYPE_BOOL_TRUE)?;
        } else {
            self.data.write_u8((1 << 5) | TYPE_BOOL_FALSE)?;
        }
        self.data.write_u8(tag)
    }
}

impl Default for TlvBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum TlvItemValue {
    Int(u64),
    Bool(bool),
    String(String),
    OctetString(Vec<u8>),
    List(Vec<TlvItem>),
    Invalid(),
}

#[derive(Debug)]
pub struct TlvItem {
    pub tag: u8,
    pub value: TlvItemValue,
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
    pub fn get_int(&self, tag: &[u8]) -> Option<u64> {
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
        match tp {
            TYPE_INT_1 => {
                let tag = read_tag(tagctrl, cursor)?;
                let value = cursor.read_u8()?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Int(value as u64),
                };
                container.push(item);
            }
            TYPE_UINT_1 => {
                let tag = read_tag(tagctrl, cursor)?;
                let value = cursor.read_u8()?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Int(value as u64),
                };
                container.push(item);
            }
            TYPE_UINT_2 => {
                let tag = read_tag(tagctrl, cursor)?;
                let value = cursor.read_u16::<LittleEndian>()?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Int(value as u64),
                };
                container.push(item);
            }
            TYPE_UINT_4 => {
                let tag = read_tag(tagctrl, cursor)?;
                let value = cursor.read_u32::<LittleEndian>()?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Int(value as u64),
                };
                container.push(item);
            }
            TYPE_BOOL_FALSE => {
                let tag = read_tag(tagctrl, cursor)?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Bool(false),
                };
                container.push(item);
            }
            TYPE_BOOL_TRUE => {
                let tag = read_tag(tagctrl, cursor)?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Bool(true),
                };
                container.push(item);
            }
            0xc => {
                // utf8 string
                let tag = read_tag(tagctrl, cursor)?;
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
                let tag = read_tag(tagctrl, cursor)?;
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
                let tag = read_tag(tagctrl, cursor)?;
                let size = cursor.read_u16::<LittleEndian>()?;
                let mut value = vec![0; size as usize];
                cursor.read_exact(&mut value)?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::OctetString(value),
                };
                container.push(item);
            }
            0x15 => {
                //list
                let tag = read_tag(tagctrl, cursor)?;
                let mut c2 = Vec::new();
                decode(cursor, &mut c2)?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::List(c2),
                };
                container.push(item);
            }
            0x16 => {
                //list
                let tag = read_tag(tagctrl, cursor)?;
                let mut c2 = Vec::new();
                decode(cursor, &mut c2)?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::List(c2),
                };
                container.push(item);
            }
            0x17 => {
                //list
                let tag = read_tag(tagctrl, cursor)?;
                let mut c2 = Vec::new();
                decode(cursor, &mut c2)?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::List(c2),
                };
                container.push(item);
            }
            0x18 => return Ok(()),
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
    UInt8(u8),
    UInt16(u16),
    UInt32(u32),
    UInt64(u64),
    Bool(bool),
    String(String),
    OctetString(Vec<u8>),
    StructAnon(Vec<TlvItemEnc>),
    Invalid(),
}

#[derive(Debug)]
pub struct TlvItemEnc {
    pub tag: u8,
    pub value: TlvItemValueEnc,
}

impl TlvItemEnc {
    fn encode_internal(&self, buf: &mut TlvBuffer) -> Result<()> {
        match &self.value {
            TlvItemValueEnc::Int8(i) => {
                buf.write_int8(self.tag, *i)?;
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
            TlvItemValueEnc::String(_) => {}
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
    use super::{TlvBuffer, TlvItemEnc, TlvItemValueEnc};

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
        println!("{}", hex::encode(o));

        let mut tlv = TlvBuffer::new();
        tlv.write_anon_struct().unwrap();
        tlv.write_octetstring(0x1, &[1, 2, 3]).unwrap();
        tlv.write_struct_end().unwrap();
        println!("{}", hex::encode(tlv.data));

        let t1 = TlvItemEnc {
            tag: 0,
            value: TlvItemValueEnc::StructAnon(vec![TlvItemEnc {
                tag: 1,
                value: TlvItemValueEnc::OctetString(vec![1, 2, 3]),
            }]),
        }
        .encode()
        .unwrap();
        println!("{}", hex::encode(t1));
    }
}
