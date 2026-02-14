
import xml.etree.ElementTree as ET
import os




def make_identifier(i):
  if i[0].isdigit(): i = '_' + i
  return i.replace(' ', '_').replace('.', '_').replace('-', '_').replace('/', '_')
def make_identifier_upper(i):
  return make_identifier(i).upper()



def gen_cluster(fname, file, file_names):
  fname2 = fname.replace('-', '_')
  shortfname = fname2.split('.')[0]

  tree = ET.parse('xml/'+fname)
  root = tree.getroot()



  cluster_name = None

  file.write('// --- {} ---\n'.format(shortfname))
  for cluster_ids in root.findall('clusterIds'):
    for cluster_id in cluster_ids.findall('clusterId'):
      if not 'id' in cluster_id.attrib:
        print('cluster id not present for {}'.format(fname))
        continue
      cluster_name = make_identifier_upper(cluster_id.attrib['name'])
      cluster_idx = cluster_id.attrib['id']
      file.write('pub const CLUSTER_ID_{}: u32 = {};\n'.format(cluster_name, cluster_idx))
      file_names.write('    {} => Some("{}"),\n'.format(cluster_idx, cluster_id.attrib['name']))

  if cluster_name == None:
    print('no cluster defined in file {}', fname)
    file.write('// no cluster defined\n\n')
    return

  attr = {}
  for attributes in root.findall('attributes'):
    for attribute in attributes.findall('attribute'):
      name = make_identifier_upper(attribute.attrib['name'])
      if name in attr: continue
      attr[name] = True
      file.write('pub const CLUSTER_{}_ATTR_ID_{}: u32 = {};\n'.format(cluster_name, name, attribute.attrib['id']))
  
  cmd = {}
  for commands in root.findall('commands'):
    for command in commands.findall('command'):
      name = make_identifier_upper(command.attrib['name'])
      if name in cmd: continue
      cmd[name] = True
      file.write('pub const CLUSTER_{}_CMD_ID_{}: u32 = {};\n'.format(cluster_name, name, command.attrib['id']))
  file.write('\n')



outfile = open('defs.rs', 'w')
outfile.write('//! Matter cluster, attributes and commands identifiers\n\n\n')
#outfile.write('#![allow(non_snake_case)]\n')
#outfile.write('#![allow(non_camel_case_types)]\n')
#outfile.write('#![allow(dead_code)]\n')
#outfile.write('#![allow(clippy::upper_case_acronyms)]\n')
#outfile.write('#![allow(clippy::enum_variant_names)]\n')



outfile_names = open('names.rs', 'w')
outfile_names.write('//! Convert cluster IDs to names\n\n\n')
outfile_names.write('pub fn get_cluster_name(id: u32) -> Option<&\'static str> {\n')
outfile_names.write('  match id {\n')

files = os.listdir(path='xml')
for file in files:
  if file.endswith('.xml'):
    gen_cluster(file, outfile, outfile_names)
outfile.close()


outfile_names.write('    _ => None\n')
outfile_names.write('  }')
outfile_names.write('}')
outfile_names.close()



