
import xml.etree.ElementTree as ET
import os





def gen_device_type(fname, file, path):
  fname2 = fname.replace('-', '_')
  shortfname = fname2.split('.')[0]

  tree = ET.parse(os.path.join(path, fname))
  root = tree.getroot()


  device_type_name = root.attrib['name']
  if not 'id' in root.attrib: return
  device_type_idx = root.attrib['id']
  file.write('    {} => Some("{}"),\n'.format(device_type_idx, device_type_name))



outfile_names = open('dt_names.rs', 'w')
outfile_names.write('// do not edit - this file is generated\n\n\n')
outfile_names.write('pub fn get_device_type_name(id: u32) -> Option<&\'static str> {\n')
outfile_names.write('  match id {\n')



path = 'xml-devicetypes-1.4.2'

files = os.listdir(path=path)
for file in files:
  if file.endswith('.xml'):
    gen_device_type(file, outfile_names, path=path)


outfile_names.write('    _ => None\n')
outfile_names.write('  }')
outfile_names.write('}')
outfile_names.close()



