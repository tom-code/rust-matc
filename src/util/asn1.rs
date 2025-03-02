#![allow(dead_code)]

use std::io::Cursor;
use std::io::Read;
use std::io::Result;

use byteorder::ReadBytesExt;
use byteorder::WriteBytesExt;

#[derive(Debug, Clone)]
pub enum Class {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

#[derive(Debug, Clone)]
pub struct TagSpec {
    class: Class,
    constructed: bool,
    tag: u16,
}

pub fn read_tag(cursor: &mut Cursor<&[u8]>) -> Result<u8> {
    cursor.read_u8()
}

pub fn read_tag_s(cursor: &mut Cursor<&[u8]>) -> Result<TagSpec> {
    let first = cursor.read_u8()?;
    let class = {
        match first & 0xc0 {
            0 => Class::Universal,
            0x40 => Class::Application,
            0x80 => Class::ContextSpecific,
            0xc0 => Class::Private,
            _ => Class::Universal,
        }
    };
    let constructed = (first & 0x20) == 0x20;
    if (first & 0x1f) != 0x1f {
        Ok(TagSpec {
            class,
            constructed,
            tag: (first & 0x1f) as u16,
        })
    } else {
        let mut tag: u16 = 0;
        loop {
            let next = cursor.read_u8()?;
            tag <<= 7;
            tag |= (next & 0x7f) as u16;
            if next & 0x80 == 0 {
                break Ok(TagSpec {
                    class,
                    constructed,
                    tag,
                });
            }
        }
    }
}

pub fn read_size(cursor: &mut Cursor<&[u8]>) -> Result<usize> {
    let b1 = cursor.read_u8()? as usize;
    if b1 & 0x80 == 0 {
        return Ok(b1);
    }
    let size = b1 & 0x7f;
    let mut out = 0;
    for _ in 0..size {
        let c = cursor.read_u8()? as usize;
        out = (out << 8) + c;
    }
    Ok(out)
}

pub fn read_uint(cursor: &mut Cursor<&[u8]>) -> Result<u32> {
    read_tag(cursor)?;
    let size = read_size(cursor)?;
    let mut out = 0;
    for _ in 0..size {
        let c = cursor.read_u8()? as u32;
        out <<= 8;
        out |= c;
    }
    Ok(out)
}

pub fn read_string(cursor: &mut Cursor<&[u8]>) -> Result<String> {
    read_tag(cursor)?;
    let size = read_size(cursor)?;
    let mut buf = vec![0; size];
    cursor.read_exact(&mut buf)?;
    match std::str::from_utf8(&buf) {
        Ok(s) => Ok(s.to_owned()),
        Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
    }
}

pub fn write_tag(buf: &mut Vec<u8>, tag: u8) -> Result<()> {
    buf.write_u8(tag)
}

pub fn write_tag_s(buf: &mut Vec<u8>, class: u8, contructed: bool, tag: u16) -> Result<()> {
    let mut first = class;
    if contructed {
        first |= 0x20
    }
    if tag <= 30 {
        first |= tag as u8;
        buf.write_u8(first)
    } else {
        first |= 0x1f;
        buf.write_u8(first)?;
        let mut tmp = tag;
        while tmp > 0 {
            if tmp > 0x7f {
                buf.write_u8((tmp & 0x7f) as u8)?;
                tmp >>= 7;
            } else {
                buf.write_u8(tmp as u8)?;
                break;
            }
        }
        Ok(())
    }
}
pub fn write_tag_s2(buf: &mut Vec<u8>, ctag: &TagSpec) -> Result<()> {
    let class = {
        match ctag.class {
            Class::Universal => 0,
            Class::Application => 0x40,
            Class::ContextSpecific => 0x80,
            Class::Private => 0xc0,
        }
    };
    write_tag_s(buf, class, ctag.constructed, ctag.tag)
}

pub fn write_len(buf: &mut Vec<u8>, len: u8) -> Result<()> {
    buf.write_u8(len)
}

pub fn write_enum(buf: &mut Vec<u8>, val: u8) -> Result<()> {
    write_tag(buf, 0xa)?;
    write_len(buf, 1)?;
    buf.write_u8(val)
}
fn write_octet_string(buf: &mut Vec<u8>, val: &[u8]) -> Result<()> {
    write_tag(buf, 0x4)?;
    write_len(buf, val.len() as u8)?;
    buf.extend_from_slice(val);
    Ok(())
}
fn write_string(buf: &mut Vec<u8>, val: &str) -> Result<()> {
    write_tag(buf, 0xc)?;
    let bytes = val.as_bytes();
    write_len(buf, bytes.len() as u8)?;
    buf.extend_from_slice(bytes);
    Ok(())
}
fn write_string_with_tag(buf: &mut Vec<u8>, tag: u8, val: &str) -> Result<()> {
    write_tag(buf, tag)?;
    let bytes = val.as_bytes();
    write_len(buf, bytes.len() as u8)?;
    buf.extend_from_slice(bytes);
    Ok(())
}
fn write_bool(buf: &mut Vec<u8>, val: bool) -> Result<()> {
    write_tag(buf, 0x1)?;
    write_len(buf, 1)?;
    if val {
        buf.write_u8(0xff)?;
    } else {
        buf.write_u8(0)?;
    }
    Ok(())
}

fn write_octet_string_with_tag(buf: &mut Vec<u8>, tag: u8, val: &[u8]) -> Result<()> {
    write_tag(buf, tag)?;
    write_len(buf, val.len() as u8)?;
    buf.extend_from_slice(val);
    Ok(())
}

pub fn write_int(buf: &mut Vec<u8>, val: u32) -> Result<()> {
    write_tag(buf, 0x2)?;
    if val < 0x80 {
        write_len(buf, 1)?;
        buf.write_u8(val as u8)
    } else if val < 0x8000 {
        write_len(buf, 2)?;
        buf.write_u8((val >> 8) as u8)?;
        buf.write_u8(val as u8)
    } else if val < 0x800000 {
        write_len(buf, 3)?;
        buf.write_u8((val >> 16) as u8)?;
        buf.write_u8((val >> 8) as u8)?;
        buf.write_u8(val as u8)
    } else {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}

#[derive(Debug, Clone)]
struct Asn1EncoderStackEntry {
    pos: usize,
}

#[derive(Debug, Clone)]
pub struct Encoder {
    buffer: Vec<u8>,
    stack: Vec<Asn1EncoderStackEntry>,
}

impl Encoder {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            stack: Vec::new(),
        }
    }
    pub fn start_seq(&mut self, tag: u8) -> Result<()> {
        write_tag(&mut self.buffer, tag)?;
        self.stack.push(Asn1EncoderStackEntry {
            pos: self.buffer.len() - 1,
        });
        write_len(&mut self.buffer, 0)
    }
    pub fn fix(&mut self) {
        while !self.stack.is_empty() {
            self.end_seq()
        }
    }
    pub fn end_seq(&mut self) {
        let i = self.stack.pop();
        if let Some(a) = i {
            let s = self.buffer.len() - a.pos - 2;
            //self.buffer[a.pos + 1] = s as u8;
            if s < 0x80 {
                self.buffer[a.pos + 1] = s as u8;
            } else if s <= 0xff {
                self.buffer[a.pos + 1] = 0x81;
                self.buffer.insert(a.pos + 2, s as u8);
            } else {
                self.buffer[a.pos + 1] = 0x82;
                self.buffer.insert(a.pos + 2, (s >> 8) as u8);
                self.buffer.insert(a.pos + 3, s as u8);
            }
        }
    }
    pub fn write_octet_string(&mut self, val: &[u8]) -> Result<()> {
        write_octet_string(&mut self.buffer, val)
    }
    pub fn write_string(&mut self, val: &str) -> Result<()> {
        write_string(&mut self.buffer, val)
    }
    pub fn write_string_with_tag(&mut self, tag: u8, val: &str) -> Result<()> {
        write_string_with_tag(&mut self.buffer, tag, val)
    }
    pub fn write_octet_string_with_tag(&mut self, tag: u8, val: &[u8]) -> Result<()> {
        write_octet_string_with_tag(&mut self.buffer, tag, val)
    }
    pub fn write_enum(&mut self, val: u8) -> Result<()> {
        write_enum(&mut self.buffer, val)
    }
    pub fn write_int(&mut self, val: u32) -> Result<()> {
        write_int(&mut self.buffer, val)
    }
    pub fn write_bool(&mut self, val: bool) -> Result<()> {
        write_bool(&mut self.buffer, val)
    }
    pub fn write_oid(&mut self, val: &str) -> Result<()> {
        match const_oid::ObjectIdentifier::new(val) {
            Ok(o) => self.write_octet_string_with_tag(0x6, o.as_bytes()),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("can't parse oid {:?}", e),
            )),
        }
    }

    pub fn encode(mut self) -> Vec<u8> {
        self.fix();
        self.buffer
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

#[test]
fn a_test() {
    assert_eq!(
        read_size(&mut std::io::Cursor::new(&[0x82, 0x27, 0x32])).unwrap(),
        10034
    );
    assert_eq!(read_size(&mut std::io::Cursor::new(&[0x08])).unwrap(), 8);
    let mut buf = Vec::new();
    write_int(&mut buf, 127).unwrap();
    assert_eq!(buf, vec![0x02, 0x01, 0x7f]);

    let mut buf = Vec::new();
    write_int(&mut buf, 128).unwrap();
    assert_eq!(buf, vec![0x02, 0x02, 0x0, 0x80]);

    let mut buf = Vec::new();
    write_int(&mut buf, 256).unwrap();
    assert_eq!(buf, vec![0x02, 0x02, 0x1, 0x0]);

    let mut buf = Vec::new();
    write_bool(&mut buf, true).unwrap();
    assert_eq!(buf, vec![0x01, 0x01, 0xff]);
}

#[test]
fn tag_test() {
    let mut buf = Vec::new();
    write_tag_s(&mut buf, 0xc0, false, 10).unwrap();
    write_len(&mut buf, 3).unwrap();
    std::io::Write::write_all(&mut buf, "abc".as_bytes()).unwrap();
    let mut cursor = Cursor::new(buf.as_ref());
    println!(
        "{:?} {:?}",
        hex::encode(&buf),
        read_tag_s(&mut cursor).unwrap()
    );

    let mut buf = Vec::new();
    write_tag_s(&mut buf, 0xc0, false, 31).unwrap();
    write_len(&mut buf, 3).unwrap();
    std::io::Write::write_all(&mut buf, "abc".as_bytes()).unwrap();
    let mut cursor = Cursor::new(buf.as_ref());
    println!(
        "{:?} {:?}",
        hex::encode(&buf),
        read_tag_s(&mut cursor).unwrap()
    );

    let mut buf = Vec::new();
    write_tag_s(&mut buf, 0xc0, false, 100).unwrap();
    write_len(&mut buf, 3).unwrap();
    std::io::Write::write_all(&mut buf, "abc".as_bytes()).unwrap();
    let mut cursor = Cursor::new(buf.as_ref());
    println!(
        "{:?} {:?}",
        hex::encode(&buf),
        read_tag_s(&mut cursor).unwrap()
    );
}
