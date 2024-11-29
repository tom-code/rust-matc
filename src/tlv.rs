use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Result, Write};

pub struct TlvBuffer {
    pub data: Vec<u8>,
}

const TYPE_UINT_1: u8 = 4;
const TYPE_UINT_2: u8 = 5;
const TYPE_UINT_4: u8 = 6;
const TYPE_UINT_8: u8 = 7;
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
            ctrl |= 0x11;
            self.data.write_u8(ctrl)?;
            self.data.write_u8(tag)?;
            self.data.write_u16::<LittleEndian>(data.len() as u16)?;
        } else {
            ctrl |= 0x10;
            self.data.write_u8(ctrl)?;
            self.data.write_u8(tag)?;
            self.data.write_u8(data.len() as u8)?;
        }
        self.data.write_all(data)?;
        Ok(())
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
            self.data.write_u8((1 << 5) | 0x9)?;
        } else {
            self.data.write_u8((1 << 5) | 0x8)?;
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
            0 => {
                let tag = read_tag(tagctrl, cursor)?;
                let value = cursor.read_u8()?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Int(value as u64),
                };
                container.push(item);
            }
            4 => {
                let tag = read_tag(tagctrl, cursor)?;
                let value = cursor.read_u8()?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Int(value as u64),
                };
                container.push(item);
            }
            5 => {
                let tag = read_tag(tagctrl, cursor)?;
                let value = cursor.read_u16::<LittleEndian>()?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Int(value as u64),
                };
                container.push(item);
            }
            8 => {
                let tag = read_tag(tagctrl, cursor)?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Bool(true),
                };
                container.push(item);
            }
            9 => {
                let tag = read_tag(tagctrl, cursor)?;
                let item = TlvItem {
                    tag,
                    value: TlvItemValue::Bool(false),
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
            0x10 => {
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
            0x11 => {
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
