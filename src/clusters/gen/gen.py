
import xml.etree.ElementTree as ET
import os



default_types = {
  'vendor-id': 'u16',
  'fabric-id': 'u64',
  'fabric-idx': 'u8',
  'cluster-id': 'u32',
  'artrib-id': 'u32',
  'field-id': 'u32',
  'endpoint-no': 'u16',
  'node-id': 'u64',
  'octstr': 'Vec<u8>',
  'string': 'String',
  'ref_SubjectId': 'u64',
  'uint8': 'u8',
  'uint16': 'u16',
  'uint32': 'u32',
  'uint64': 'u64',
  'enum8': 'u8',
  'enum16': 'u16',
  'epoch-s': 'u64',
  'int16': 'u16',
}

tlv_getters = {
  'u8': 'get_u8',
  'u16': 'get_u16',
  'u32': 'get_u32',
  'u64': 'get_u64',
  'bool': 'get_bool',
  'Vec<u8>': 'get_octet_string_owned',
  'String': 'get_string_owned'
}

def get_tlv_getter(typ):
  if typ in tlv_getters: return tlv_getters[typ]
  return 'get_??????'

tlv_setters = {
  'u8': ('write_uint8', '*'),
  'u16': ('write_uint16', '*'),
  'u32': ('write_uint32', '*'),
  'u64': ('write_uint64', '*'),
  'bool': ('write_bool', '*'),
  'Vec<u8>': ('write_octetstring',''),
  'String': ('write_string', ''),
  'ref_SubjectId': ('write_uint64', '*')
}


def get_tlv_setter(typ):
  if typ in tlv_setters: return tlv_setters[typ]
  return ('write_??????', '*')

def convert_type(t):
  if t in default_types:
    return default_types[t]
  return t

def make_identifier(i):
  if i[0].isdigit(): i = '_' + i
  return i.replace(' ', '_').replace('.', '_').replace('-', '_').replace('/', '_')
def make_identifier_upper(i):
  return make_identifier(i).upper()


def write_struct(file, name, struct):
  file.write('#[derive(Debug)]\n')
  file.write('pub struct {} {{\n'.format(name))
  for field in struct.findall('field'):
    if not 'type' in field.attrib: continue
    typ = convert_type(field.attrib['type'])
    file.write('  {}: Option<{}>,\n'.format(field.attrib['name'], typ))
  file.write('}\n')


  file.write('impl {} {{\n'.format(name))

  file.write('  pub fn decode(tlv: &TlvItem) -> Self {\n')
  for field in struct.findall('field'):
    if not 'id' in field.attrib: continue
    idd = field.attrib['id']
    if not 'type' in field.attrib: continue
    typ = convert_type(field.attrib['type'])
    if 'Enum' in typ:
      file.write('    let {} = {{\n'.format(field.attrib['name']))
      file.write('      let i = tlv.get_int(&[{}]);\n'.format(idd))
      file.write('      match i {\n')
      file.write('        Some(n) => {}::from_u64(n),\n'.format(field.attrib['type']))
      file.write('        None => None\n')
      file.write('      }\n')
      file.write('    };\n')
    else:
      tlv_getter = get_tlv_getter(typ)
      file.write('    let {} = tlv.{}(&[{}]);\n'.format(field.attrib['name'], tlv_getter, idd))
  file.write('    Self {\n')
  for field in struct.findall('field'):
    if not 'type' in field.attrib: continue
    file.write('    {},\n'.format(field.attrib['name']))
  file.write('    }\n')
  file.write('  }\n')

  file.write('  pub fn encode(&self) -> Result<Vec<u8>> {\n')
  file.write('    let mut tlv = TlvBuffer::new();\n')
  for field in struct.findall('field'):
    if not 'id' in field.attrib: continue
    idd = field.attrib['id']
    if not 'type' in field.attrib: continue
    typ = convert_type(field.attrib['type'])
    if 'Enum' in typ:
      fname = field.attrib['name']
      file.write('    if let Some(v) = &self.{} {{\n'.format(fname))
      file.write('      tlv.write_uint64({}, v.to_u64())?;\n'.format(idd))
      file.write('    };\n')
    else:
      (tlv_setter, pref) = get_tlv_setter(typ)
      fname = field.attrib['name']
      file.write('    if let Some(v) = &self.{} {{\n'.format(fname))
      file.write('      tlv.{}({}, {}v)?;\n'.format(tlv_setter, idd, pref))
      file.write('    };\n')
  file.write('    Ok(tlv.data)\n')
  file.write('  }\n')


  file.write('}\n')

def gen_cluster(fname):
  fname2 = fname.replace('-', '_')
  outfname = fname2.split('.')[0]+'.rs'
  shortfname = fname2.split('.')[0]
  print(outfname)

  tree = ET.parse('xml/'+fname)
  root = tree.getroot()
  #print(root.tag)

  #for child in root:
  #    print(child.tag, child.attrib)

  file = open(outfname, 'w')
  global libfile
  libfile.write('pub mod {};\n'.format(shortfname));

  file.write('// this file is generated from {}\n'.format(fname))
  file.write('#![allow(non_snake_case)]\n')
  file.write('#![allow(non_camel_case_types)]\n')
  file.write('#![allow(dead_code)]\n')
  file.write('#![allow(clippy::upper_case_acronyms)]\n')
  file.write('#![allow(clippy::enum_variant_names)]\n')
  #file.write('use crate::tlv::TlvItem;\n')
  #file.write('use crate::tlv::TlvBuffer;\n')
  #file.write('use anyhow::Result;\n')


  for cluster_ids in root.findall('clusterIds'):
    for cluster_id in cluster_ids.findall('clusterId'):
      if not 'id' in cluster_id.attrib:
        print('cluster id not present for {}'.format(fname))
        continue
      file.write('pub const CLUSTER_ID_{}:u32 = {};\n'.format(make_identifier_upper(cluster_id.attrib['name']), cluster_id.attrib['id']))


  attr = {}
  for attributes in root.findall('attributes'):
    for attribute in attributes.findall('attribute'):
      name = make_identifier_upper(attribute.attrib['name'])
      if name in attr: continue
      attr[name] = True
      file.write('pub const ATTRIB_ID_{}:u32 = {};\n'.format(name, attribute.attrib['id']))
  
  cmd = {}
  for commands in root.findall('commands'):
    for command in commands.findall('command'):
      name = make_identifier_upper(command.attrib['name'])
      if name in cmd: continue
      cmd[name] = True
      file.write('pub const COMMAND_ID_{}:u32 = {};\n'.format(name, command.attrib['id']))

  #for commands in root.findall('commands'):
  #  for command in commands.findall('command'):
  #    name = command.attrib['name']
  #    write_struct(file, name+'CommandArgs', command)


  for datatypes in root.findall('dataTypes'):
    for enum in datatypes.findall('enum'):
      enum_name = make_identifier(enum.attrib['name'])
      if len(enum.findall('item')) == 0: continue
      file.write('#[derive(Debug)]\n')
      file.write('enum {} {{\n'.format(enum_name))
      for item in enum.findall('item'):
        if not 'value' in item.attrib: continue
        file.write('  {},\n'.format(make_identifier(item.attrib['name'])))
      file.write('}\n')

      file.write('impl {} {{\n'.format(enum_name))
      file.write('  fn to_u64(&self) -> u64 {{\n'.format(enum.attrib['name']))
      file.write('    match *self {\n')
      for item in enum.findall('item'):
       if not 'value' in item.attrib: continue
       file.write('      {}::{} => {},\n'.format(enum_name, make_identifier(item.attrib['name']), item.attrib['value']))
      file.write('    }\n')
      file.write('  }\n')
      file.write('  fn from_u64(v: u64) -> Option<Self> {{\n'.format(enum.attrib['name']))
      file.write('    match v {\n')
      for item in enum.findall('item'):
       if not 'value' in item.attrib: continue
       file.write('      {} => Some({}::{}),\n'.format(item.attrib['value'], enum_name, make_identifier(item.attrib['name'])))
      file.write('      _ => None,\n')
      file.write('    }\n')
      file.write('  }\n')
      file.write('}\n')


    #for struct in datatypes.findall('struct'):
    #  name = struct.attrib['name']
    #  write_struct(file, name, struct)



  file.close()


libfile = open('mod.rs', 'w')
files = os.listdir(path='xml')
for file in files:
  if file.endswith('.xml'):
    gen_cluster(file)
libfile.close()
