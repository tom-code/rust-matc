#!/usr/bin/env python3
"""
Python script to generate Rust code for Matter TLV command encoding.

This script parses all Matter cluster XML files in a directory and generates Rust code 
to encode TLV structures for commands using the TlvItemEnc API.

Usage:
    python generate.py <xml_directory> <output_directory>
"""

import xml.etree.ElementTree as ET
import sys
import os
import glob
import re
from typing import Dict, List, Optional, Tuple

# Helper constants / utilities to reduce duplication when generating Rust code
NUMERIC_OR_ID_TYPES = {
    'devtype-id', 'cluster-id', 'endpoint-no', 'node-id', 'vendor-id', 'epoch-s', 'subject-id'
}

def is_numeric_or_id_type(t: str) -> bool:
    """Return True if the Matter type is numeric or a well-known ID type."""
    return t.startswith('uint') or t.startswith('int') or t in NUMERIC_OR_ID_TYPES

def build_numeric_field_assignment(var_name: str, field_id: int, matter_type: str, indent: str = '                ') -> str:
    """Generate Rust code snippet for assigning a numeric/ID field with proper casting."""
    rust_type = MatterType.get_rust_type(matter_type)
    if rust_type == 'u64':
        return f"{indent}{var_name}: item.get_int(&[{field_id}]),"
    else:
        return f"{indent}{var_name}: item.get_int(&[{field_id}]).map(|v| v as {rust_type}),"

def build_nested_numeric_assignment(var_name: str, field_id: int, matter_type: str, list_item_var: str = 'list_item', indent: str = '                                ') -> str:
    rust_type = MatterType.get_rust_type(matter_type)
    if rust_type == 'u64':
        return f"{indent}{var_name}: {list_item_var}.get_int(&[{field_id}]),"
    else:
        return f"{indent}{var_name}: {list_item_var}.get_int(&[{field_id}]).map(|v| v as {rust_type}),"


def convert_to_snake_case(name: str) -> str:
    """
    Convert CamelCase to snake_case with proper handling of abbreviations.
    
    Examples:
    - ClearRFIDCode -> clear_rfid_code
    - SetPINCode -> set_pin_code
    - OnOff -> on_off
    - XMLHttpRequest -> xml_http_request
    - WiFiNetworkManagement -> wifi_network_management
    """
    # Handle specific common abbreviations by direct replacement
    replacements = [
        ('WiFi', 'Wifi'),
        ('RFID', 'Rfid'),
        ('HTTP', 'Http'),
        ('HTTPS', 'Https'),
        ('XML', 'Xml'),
        ('JSON', 'Json'),
        ('API', 'Api'),
        ('URL', 'Url'),
        ('URI', 'Uri'),
        ('UUID', 'Uuid'),
        ('TCP', 'Tcp'),
        ('UDP', 'Udp'),
        ('MAC', 'Mac'),
        ('DNS', 'Dns'),
        ('SSL', 'Ssl'),
        ('TLS', 'Tls'),
        ('PIN', 'Pin'),
        ('ACL', 'Acl'),
        ('ICD', 'Icd'),
        ('OTA', 'Ota'),
        ('PKI', 'Pki'),
        ('CO', 'Co')
    ]
    
    # Apply replacements
    for old, new in replacements:
        name = name.replace(old, new)
    
    # Handle sequences of uppercase letters followed by lowercase (e.g., XMLHttp -> XML_Http)
    name = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', name)
    
    # Handle lowercase followed by uppercase (e.g., getHTTP -> get_HTTP)
    name = re.sub(r'([a-z\d])([A-Z])', r'\1_\2', name)
    
    # Clean up any multiple underscores and convert to lowercase
    name = re.sub(r'_+', '_', name).lower()
    
    # Remove leading/trailing underscores
    return name.strip('_')


def escape_rust_keyword(name: str) -> str:
    """
    Escape Rust keywords by appending '_' suffix.
    
    Examples:
    - type -> type_
    - match -> match_
    - if -> if_
    """
    # List of Rust keywords that need to be escaped
    rust_keywords = {
        'as', 'break', 'const', 'continue', 'crate', 'else', 'enum', 'extern',
        'false', 'fn', 'for', 'if', 'impl', 'in', 'let', 'loop', 'match', 'mod',
        'move', 'mut', 'pub', 'ref', 'return', 'self', 'Self', 'static', 'struct',
        'super', 'trait', 'true', 'type', 'unsafe', 'use', 'where', 'while',
        'async', 'await', 'dyn', 'abstract', 'become', 'box', 'do', 'final',
        'macro', 'override', 'priv', 'typeof', 'unsized', 'virtual', 'yield',
        'try', 'union'
    }
    
    if name in rust_keywords:
        return f"{name}_"
    return name


class MatterStruct:
    """Represents a Matter struct definition."""
    
    def __init__(self, name: str):
        self.name = name
        self.fields: List[Tuple[int, str, str, Optional[str]]] = []  # (id, name, type, entry_type)
    
    def add_field(self, field_id: int, field_name: str, field_type: str, entry_type: Optional[str] = None):
        """Add a field to this struct."""
        self.fields.append((field_id, field_name, field_type, entry_type))
    
    def get_rust_struct_name(self) -> str:
        """Convert struct name to PascalCase Rust struct name."""
        # Remove "Struct" suffix if present
        name = self.name.replace('Struct', '')
        # Split on capital letters and rejoin in PascalCase
        # Handle cases like "DeviceTypeStruct" -> "DeviceType"
        words = re.findall(r'[A-Z][a-z]*', name)
        return ''.join(words) if words else name
    
    def generate_rust_struct(self, structs: Dict[str, 'MatterStruct'] = None) -> str:
        """Generate Rust struct definition."""
        struct_name = self.get_rust_struct_name()
        
        field_definitions = []
        for field_id, field_name, field_type, entry_type in self.fields:
            rust_field_name = convert_to_snake_case(field_name)
            rust_field_name = escape_rust_keyword(rust_field_name)  # Escape Rust keywords
            
            if field_type == 'list' and entry_type:
                # Handle list fields with specific entry types
                if entry_type.endswith('Struct'):
                    # Custom struct type - convert to PascalCase
                    entry_rust_type = entry_type.replace('Struct', '')
                    entry_rust_type = ''.join(word.capitalize() for word in re.findall(r'[A-Z][a-z]*', entry_rust_type))
                    rust_type = f"Vec<{entry_rust_type}>"
                else:
                    # Primitive type or known type
                    entry_rust_type = MatterType.get_rust_type(entry_type)
                    rust_type = f"Vec<{entry_rust_type}>"
            elif field_type.endswith('Struct'):
                # Handle custom struct type
                if structs and field_type in structs:
                    # Use the struct's rust name
                    rust_type = structs[field_type].get_rust_struct_name()
                else:
                    # Fallback: convert struct name
                    rust_type = field_type.replace('Struct', '')
                    rust_type = ''.join(word.capitalize() for word in re.findall(r'[A-Z][a-z]*', rust_type))
            else:
                rust_type = MatterType.get_rust_type(field_type)
            
            # Make all struct fields optional since they might not be present in TLV
            field_definitions.append(f"    pub {rust_field_name}: Option<{rust_type}>,")
        
        fields_str = "\n".join(field_definitions)
        
        return f'''#[derive(Debug, serde::Serialize)]
pub struct {struct_name} {{
{fields_str}
}}'''
    
    def generate_decode_function(self, is_list: bool = False) -> str:
        """Generate decode function for this struct."""
        struct_name = self.get_rust_struct_name()
        func_name = f"decode_{convert_to_snake_case(self.name)}"
        
        if is_list:
            func_name += "_list"
            return_type = f"Vec<{struct_name}>"
        else:
            return_type = struct_name
        
        # Generate field assignments
        field_assignments = []
        for field_id, field_name, field_type, entry_type in self.fields:
            rust_field_name = convert_to_snake_case(field_name)
            rust_field_name = escape_rust_keyword(rust_field_name)  # Escape Rust keywords
            
            if field_type == 'list' and entry_type:
                # Handle list fields with specific entry types
                if entry_type.endswith('Struct'):
                    # Custom struct - need complex decoding
                    field_assignments.append(f"                {rust_field_name}: None, // TODO: Implement {entry_type} list decoding")
                elif entry_type == 'SubjectID':
                    # SubjectID is typically u64
                    field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(tlv::TlvItemValue::List(l)) = item.get(&[{field_id}]) {{
                        let subjects: Vec<u64> = l.iter().filter_map(|e| {{
                            if let tlv::TlvItemValue::Int(v) = &e.value {{
                                Some(*v)
                            }} else {{
                                None
                            }}
                        }}).collect();
                        Some(subjects)
                    }} else {{
                        None
                    }}
                }},''')
                else:
                    # Other primitive types in lists
                    rust_type = MatterType.get_rust_type(entry_type)
                    cast_expr = "*v" if rust_type == "u64" else f"*v as {rust_type}"
                    field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(tlv::TlvItemValue::List(l)) = item.get(&[{field_id}]) {{
                        let items: Vec<{rust_type}> = l.iter().filter_map(|e| {{
                            if let tlv::TlvItemValue::Int(v) = &e.value {{
                                Some({cast_expr})
                            }} else {{
                                None
                            }}
                        }}).collect();
                        Some(items)
                    }} else {{
                        None
                    }}
                }},''')
            elif is_numeric_or_id_type(field_type):
                rust_type = MatterType.get_rust_type(field_type)
                if rust_type == "u64":
                    # No casting needed, get_int already returns u64
                    field_assignments.append(f"                {rust_field_name}: item.get_int(&[{field_id}]),")
                else:
                    # Casting needed
                    field_assignments.append(f"                {rust_field_name}: item.get_int(&[{field_id}]).map(|v| v as {rust_type}),")
            elif field_type == 'string':
                field_assignments.append(f"                {rust_field_name}: item.get_string_owned(&[{field_id}]),")
            elif field_type == 'bool':
                field_assignments.append(f"                {rust_field_name}: item.get_bool(&[{field_id}]),")
            elif field_type == 'octstr':
                field_assignments.append(f"                {rust_field_name}: item.get_octet_string_owned(&[{field_id}]),")
            else:
                # Default to treating as integer
                field_assignments.append(f"                {rust_field_name}: item.get_int(&[{field_id}]).map(|v| v as u8),")
        
        assignments_str = "\n".join(field_assignments)
        
        if is_list:
            decode_logic = f'''    let mut res = Vec::new();
    if let tlv::TlvItemValue::List(v) = inp {{
        for item in v {{
            res.push({struct_name} {{
{assignments_str}
            }});
        }}
    }}
    Ok(res)'''
        else:
            decode_logic = f'''    if let tlv::TlvItemValue::List(fields) = inp {{
        // Single struct with fields
        let item = tlv::TlvItem {{ tag: 0, value: inp.clone() }};
        Ok({struct_name} {{
{assignments_str}
        }})
    }} else {{
        Err(anyhow::anyhow!("Expected struct fields"))
    }}'''
        
        return f'''/// Decode {self.name}
pub fn {func_name}(inp: &tlv::TlvItemValue) -> anyhow::Result<{return_type}> {{
{decode_logic}
}}'''


class MatterType:
    """Represents a Matter data type and its Rust TLV encoding equivalent."""
    
    TYPE_MAPPING = {
        'uint8': 'UInt8',
        'uint16': 'UInt16', 
        'uint32': 'UInt32',
        'uint64': 'UInt64',
        'int8': 'Int8',
        'int16': 'Int16',
        'int32': 'Int32',
        'int64': 'Int64',
        'bool': 'Bool',
        'string': 'String',
        'epoch-s': 'UInt64',
        'octstr': 'OctetString',
        'list': 'StructAnon',  # Lists are encoded as anonymous structs
        # Matter-specific ID types
        'devtype-id': 'UInt32',
        'cluster-id': 'UInt32', 
        'endpoint-no': 'UInt16',
        'node-id': 'UInt64',
        'vendor-id': 'UInt16',
        'subject-id': 'UInt64',
    }
    
    @classmethod
    def get_tlv_type(cls, matter_type: str) -> str:
        """Convert Matter type to TLV encoding type."""
        # Handle special cases
        if matter_type.endswith('Enum'):
            return 'UInt8'
        if matter_type.endswith('Bitmap'):
            return 'UInt8'
        
        return cls.TYPE_MAPPING.get(matter_type, 'UInt8')
    
    @classmethod
    def get_rust_type(cls, matter_type: str, is_list: bool = False) -> str:
        """Get the corresponding Rust type for function parameters."""
        rust_mapping = {
            'uint8': 'u8',
            'uint16': 'u16',
            'uint32': 'u32', 
            'uint64': 'u64',
            'int8': 'i8',
            'int16': 'i16',
            'int32': 'i32',
            'int64': 'i64',
            'bool': 'bool',
            'string': 'String',
            'epoch-s': 'u64',
            'octstr': 'Vec<u8>',
            # Matter-specific ID types
            'devtype-id': 'u32',
            'cluster-id': 'u32',
            'endpoint-no': 'u16',
            'vendor-id': 'u16',
            'subject-id': 'u64',
            # Matter-specific types
            'SubjectID': 'u64',
            'node-id': 'u64',
        }
        
        if matter_type.endswith('Enum'):
            base_type = 'u8'
        elif matter_type.endswith('Bitmap'):
            base_type = 'u8'
        else:
            base_type = rust_mapping.get(matter_type, 'u8')
        
        # Handle list types
        if is_list or matter_type == 'list':
            return f"Vec<{base_type}>"
        
        return base_type


class AttributeField:
    """Represents a Matter attribute."""
    
    def __init__(self, id: str, name: str, attr_type: str, default: Optional[str] = None,
                 nullable: bool = False, entry_type: Optional[str] = None):
        self.id = id
        self.name = name
        self.attr_type = attr_type
        self.default = default
        self.nullable = nullable
        self.entry_type = entry_type  # For list types
        self.is_list = attr_type == 'list'
    
    def get_rust_function_name(self) -> str:
        """Convert attribute name to snake_case Rust function name."""
        return f"decode_{escape_rust_keyword(convert_to_snake_case(self.name))}"
    
    def get_rust_return_type(self, structs: Dict[str, MatterStruct] = None) -> str:
        """Get the Rust return type for this attribute."""
        if self.is_list:
            if self.entry_type:
                # Check if it's a custom struct
                if structs and self.entry_type in structs:
                    struct_name = structs[self.entry_type].get_rust_struct_name()
                    return f"Vec<{struct_name}>"
                else:
                    # Map entry types to Rust types
                    entry_rust_type = MatterType.get_rust_type(self.entry_type)
                    return f"Vec<{entry_rust_type}>"
            else:
                # Default to Vec<String> for unknown list types
                return "Vec<String>"
        else:
            # Check if it's a custom struct
            if structs and self.attr_type in structs:
                struct_name = structs[self.attr_type].get_rust_struct_name()
                if self.nullable:
                    return f"Option<{struct_name}>"
                return struct_name
            else:
                rust_type = MatterType.get_rust_type(self.attr_type)
                if self.nullable:
                    return f"Option<{rust_type}>"
                return rust_type
    
    def generate_decode_function(self, structs: Dict[str, MatterStruct] = None) -> str:
        """Generate Rust decode function for this attribute."""
        func_name = self.get_rust_function_name()
        return_type = self.get_rust_return_type(structs)
        clean_id = self.id.replace('0x0x', '0x') if self.id.startswith('0x0x') else self.id
        
        if self.is_list:
            if self.entry_type and structs and self.entry_type in structs:
                # Use custom struct decoder
                struct = structs[self.entry_type]
                struct_name = struct.get_rust_struct_name()
                
                # Generate field assignments
                field_assignments = []
                for field_id, field_name, field_type, entry_type in struct.fields:
                    rust_field_name = convert_to_snake_case(field_name)
                    rust_field_name = escape_rust_keyword(rust_field_name)  # Escape Rust keywords
                    
                    if field_type == 'list' and entry_type:
                        # Handle list fields with specific entry types
                        if entry_type.endswith('Struct') and structs and entry_type in structs:
                            # Custom struct with known definition - generate proper decoding
                            target_struct = structs[entry_type]
                            struct_rust_name = target_struct.get_rust_struct_name()
                            
                            # Generate nested field assignments for the target struct
                            nested_assignments = []
                            for nested_id, nested_name, nested_type, nested_entry_type in target_struct.fields:
                                nested_rust_name = convert_to_snake_case(nested_name)
                                nested_rust_name = escape_rust_keyword(nested_rust_name)
                                
                                if is_numeric_or_id_type(nested_type):
                                    nested_assignments.append(build_nested_numeric_assignment(nested_rust_name, nested_id, nested_type))
                                elif nested_type == 'string':
                                    nested_assignments.append(f"                                {nested_rust_name}: list_item.get_string_owned(&[{nested_id}]),")
                                elif nested_type == 'bool':
                                    nested_assignments.append(f"                                {nested_rust_name}: list_item.get_bool(&[{nested_id}]),")
                                elif nested_type == 'octstr':
                                    nested_assignments.append(f"                                {nested_rust_name}: list_item.get_octet_string_owned(&[{nested_id}]),")
                                elif nested_type == 'list' and nested_entry_type:
                                    # Handle nested list fields with custom struct entries
                                    if nested_entry_type.endswith('Struct') and structs and nested_entry_type in structs:
                                        target_nested_struct = structs[nested_entry_type]
                                        nested_struct_rust_name = target_nested_struct.get_rust_struct_name()
                                        
                                        # Generate nested assignments for the nested struct
                                        nested_nested_assignments = []
                                        for nn_id, nn_name, nn_type, nn_entry_type in target_nested_struct.fields:
                                            nn_rust_name = convert_to_snake_case(nn_name)
                                            nn_rust_name = escape_rust_keyword(nn_rust_name)
                                            
                                            if is_numeric_or_id_type(nn_type):
                                                nested_nested_assignments.append(build_nested_numeric_assignment(nn_rust_name, nn_id, nn_type, "nested_item"))
                                            elif nn_type == 'string':
                                                nested_nested_assignments.append(f"                                        {nn_rust_name}: nested_item.get_string_owned(&[{nn_id}]),")
                                            elif nn_type == 'bool':
                                                nested_nested_assignments.append(f"                                        {nn_rust_name}: nested_item.get_bool(&[{nn_id}]),")
                                            elif nn_type == 'octstr':
                                                nested_nested_assignments.append(f"                                        {nn_rust_name}: nested_item.get_octet_string_owned(&[{nn_id}]),")
                                            else:
                                                nested_nested_assignments.append(f"                                        {nn_rust_name}: nested_item.get_int(&[{nn_id}]).map(|v| v as u8),")
                                        
                                        nested_nested_str = "\n".join(nested_nested_assignments)
                                        nested_assignments.append(f'''                                {nested_rust_name}: {{
                                    if let Some(tlv::TlvItemValue::List(nested_l)) = list_item.get(&[{nested_id}]) {{
                                        let mut nested_items = Vec::new();
                                        for nested_item in nested_l {{
                                            nested_items.push({nested_struct_rust_name} {{
{nested_nested_str}
                                            }});
                                        }}
                                        Some(nested_items)
                                    }} else {{
                                        None
                                    }}
                                }},''')
                                    else:
                                        nested_assignments.append(f"                                {nested_rust_name}: None, // TODO: Implement {nested_entry_type} nested list")
                                else:
                                    nested_assignments.append(f"                                {nested_rust_name}: list_item.get_int(&[{nested_id}]).map(|v| v as u8),")
                            
                            nested_assignments_str = "\n".join(nested_assignments)
                            
                            field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(tlv::TlvItemValue::List(l)) = item.get(&[{field_id}]) {{
                        let mut items = Vec::new();
                        for list_item in l {{
                            items.push({struct_rust_name} {{
{nested_assignments_str}
                            }});
                        }}
                        Some(items)
                    }} else {{
                        None
                    }}
                }},''')
                        elif entry_type.endswith('Struct'):
                            # Custom struct without definition - generate placeholder
                            struct_rust_name = entry_type.replace('Struct', '')
                            struct_rust_name = ''.join(word.capitalize() for word in re.findall(r'[A-Z][a-z]*', struct_rust_name))
                            field_assignments.append(f"                {rust_field_name}: None, // TODO: Implement {entry_type} list decoding")
                        elif entry_type == 'SubjectID':
                            # SubjectID is typically u64
                            field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(tlv::TlvItemValue::List(l)) = item.get(&[{field_id}]) {{
                        let subjects: Vec<u64> = l.iter().filter_map(|e| {{
                            if let tlv::TlvItemValue::Int(v) = &e.value {{
                                Some(*v)
                            }} else {{
                                None
                            }}
                        }}).collect();
                        Some(subjects)
                    }} else {{
                        None
                    }}
                }},''')
                        else:
                            # Other primitive types in lists
                            rust_type = MatterType.get_rust_type(entry_type)
                            if entry_type == 'string':
                                field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(tlv::TlvItemValue::List(l)) = item.get(&[{field_id}]) {{
                        let items: Vec<{rust_type}> = l.iter().filter_map(|e| {{
                            if let tlv::TlvItemValue::String(v) = &e.value {{
                                Some(v.clone())
                            }} else {{
                                None
                            }}
                        }}).collect();
                        Some(items)
                    }} else {{
                        None
                    }}
                }},''')
                            elif entry_type == 'octstr':
                                field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(tlv::TlvItemValue::List(l)) = item.get(&[{field_id}]) {{
                        let items: Vec<{rust_type}> = l.iter().filter_map(|e| {{
                            if let tlv::TlvItemValue::OctetString(v) = &e.value {{
                                Some(v.clone())
                            }} else {{
                                None
                            }}
                        }}).collect();
                        Some(items)
                    }} else {{
                        None
                    }}
                }},''')
                            elif entry_type == 'bool':
                                field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(tlv::TlvItemValue::List(l)) = item.get(&[{field_id}]) {{
                        let items: Vec<{rust_type}> = l.iter().filter_map(|e| {{
                            if let tlv::TlvItemValue::Bool(v) = &e.value {{
                                Some(*v)
                            }} else {{
                                None
                            }}
                        }}).collect();
                        Some(items)
                    }} else {{
                        None
                    }}
                }},''')
                            else:
                                # Numeric types (int, uint, etc.)
                                cast_expr = "*v" if rust_type == "u64" else f"*v as {rust_type}"
                                field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(tlv::TlvItemValue::List(l)) = item.get(&[{field_id}]) {{
                        let items: Vec<{rust_type}> = l.iter().filter_map(|e| {{
                            if let tlv::TlvItemValue::Int(v) = &e.value {{
                                Some({cast_expr})
                            }} else {{
                                None
                            }}
                        }}).collect();
                        Some(items)
                    }} else {{
                        None
                    }}
                }},''')
                    elif is_numeric_or_id_type(field_type):
                        field_assignments.append(build_numeric_field_assignment(rust_field_name, field_id, field_type))
                    elif field_type == 'string':
                        field_assignments.append(f"                {rust_field_name}: item.get_string_owned(&[{field_id}]),")
                    elif field_type == 'bool':
                        field_assignments.append(f"                {rust_field_name}: item.get_bool(&[{field_id}]),")
                    elif field_type == 'octstr':
                        field_assignments.append(f"                {rust_field_name}: item.get_octet_string_owned(&[{field_id}]),")
                    elif field_type.endswith('Enum'):
                        # Handle enum fields as integers
                        field_assignments.append(f"                {rust_field_name}: item.get_int(&[{field_id}]).map(|v| v as u8),")
                    elif field_type.endswith('Struct') and structs and field_type in structs:
                        # Handle nested struct fields in list items
                        nested_struct = structs[field_type]
                        nested_struct_name = nested_struct.get_rust_struct_name()
                        
                        # Generate nested field assignments for the nested struct
                        nested_assignments = []
                        for nested_id, nested_name, nested_type, nested_entry_type in nested_struct.fields:
                            nested_rust_name = convert_to_snake_case(nested_name)
                            nested_rust_name = escape_rust_keyword(nested_rust_name)
                            
                            if is_numeric_or_id_type(nested_type):
                                nested_assignments.append(build_nested_numeric_assignment(nested_rust_name, nested_id, nested_type, "nested_item"))
                            elif nested_type == 'string':
                                nested_assignments.append(f"                                {nested_rust_name}: nested_item.get_string_owned(&[{nested_id}]),")
                            elif nested_type == 'bool':
                                nested_assignments.append(f"                                {nested_rust_name}: nested_item.get_bool(&[{nested_id}]),")
                            elif nested_type == 'octstr':
                                nested_assignments.append(f"                                {nested_rust_name}: nested_item.get_octet_string_owned(&[{nested_id}]),")
                            elif nested_type.endswith('Enum'):
                                nested_assignments.append(f"                                {nested_rust_name}: nested_item.get_int(&[{nested_id}]).map(|v| v as u8),")
                            elif nested_type == 'list' and nested_entry_type:
                                # Handle list fields in nested structs
                                if nested_entry_type.endswith('Enum'):
                                    # List of enums (like CharacteristicEnum)
                                    nested_assignments.append(f'''                                {nested_rust_name}: {{
                                    if let Some(tlv::TlvItemValue::List(l)) = nested_item.get(&[{nested_id}]) {{
                                        let items: Vec<u8> = l.iter().filter_map(|e| {{
                                            if let tlv::TlvItemValue::Int(v) = &e.value {{
                                                Some(*v as u8)
                                            }} else {{
                                                None
                                            }}
                                        }}).collect();
                                        Some(items)
                                    }} else {{
                                        None
                                    }}
                                }},''')
                                elif nested_entry_type.endswith('Struct') and structs and nested_entry_type in structs:
                                    # List of custom structs (like DatastoreAccessControlTargetStruct)
                                    target_nested_struct = structs[nested_entry_type]
                                    nested_struct_rust_name = target_nested_struct.get_rust_struct_name()
                                    
                                    # Generate nested assignments for the nested struct
                                    nested_nested_assignments = []
                                    for nn_id, nn_name, nn_type, nn_entry_type in target_nested_struct.fields:
                                        nn_rust_name = convert_to_snake_case(nn_name)
                                        nn_rust_name = escape_rust_keyword(nn_rust_name)
                                        
                                        if is_numeric_or_id_type(nn_type):
                                            nested_nested_assignments.append(build_nested_numeric_assignment(nn_rust_name, nn_id, nn_type, "nested_item"))
                                        elif nn_type == 'string':
                                            nested_nested_assignments.append(f"                                        {nn_rust_name}: nested_item.get_string_owned(&[{nn_id}]),")
                                        elif nn_type == 'bool':
                                            nested_nested_assignments.append(f"                                        {nn_rust_name}: nested_item.get_bool(&[{nn_id}]),")
                                        elif nn_type == 'octstr':
                                            nested_nested_assignments.append(f"                                        {nn_rust_name}: nested_item.get_octet_string_owned(&[{nn_id}]),")
                                        else:
                                            nested_nested_assignments.append(f"                                        {nn_rust_name}: nested_item.get_int(&[{nn_id}]).map(|v| v as u8),")
                                    
                                    nested_nested_str = "\n".join(nested_nested_assignments)
                                    nested_assignments.append(f'''                                {nested_rust_name}: {{
                                    if let Some(tlv::TlvItemValue::List(nested_l)) = nested_item.get(&[{nested_id}]) {{
                                        let mut nested_items = Vec::new();
                                        for nested_item in nested_l {{
                                            nested_items.push({nested_struct_rust_name} {{
{nested_nested_str}
                                            }});
                                        }}
                                        Some(nested_items)
                                    }} else {{
                                        None
                                    }}
                                }},''')
                                else:
                                    # Other list types
                                    rust_type = MatterType.get_rust_type(nested_entry_type)
                                    cast_expr = "*v" if rust_type == "u64" else f"*v as {rust_type}"
                                    nested_assignments.append(f'''                                {nested_rust_name}: {{
                                    if let Some(tlv::TlvItemValue::List(l)) = nested_item.get(&[{nested_id}]) {{
                                        let items: Vec<{rust_type}> = l.iter().filter_map(|e| {{
                                            if let tlv::TlvItemValue::Int(v) = &e.value {{
                                                Some({cast_expr})
                                            }} else {{
                                                None
                                            }}
                                        }}).collect();
                                        Some(items)
                                    }} else {{
                                        None
                                    }}
                                }},''')
                            elif nested_type.endswith('Struct') and structs and nested_type in structs:
                                # Handle deeply nested structs (struct within struct within list)
                                deep_nested_struct = structs[nested_type]
                                deep_nested_struct_name = deep_nested_struct.get_rust_struct_name()
                                
                                # Generate deep nested field assignments
                                deep_nested_assignments = []
                                for deep_id, deep_name, deep_type, deep_entry_type in deep_nested_struct.fields:
                                    deep_rust_name = convert_to_snake_case(deep_name)
                                    deep_rust_name = escape_rust_keyword(deep_rust_name)
                                    
                                    if is_numeric_or_id_type(deep_type):
                                        deep_nested_assignments.append(build_nested_numeric_assignment(deep_rust_name, deep_id, deep_type, "deep_nested_item"))
                                    elif deep_type == 'string':
                                        deep_nested_assignments.append(f"                                                {deep_rust_name}: deep_nested_item.get_string_owned(&[{deep_id}]),")
                                    elif deep_type == 'bool':
                                        deep_nested_assignments.append(f"                                                {deep_rust_name}: deep_nested_item.get_bool(&[{deep_id}]),")
                                    elif deep_type == 'octstr':
                                        deep_nested_assignments.append(f"                                                {deep_rust_name}: deep_nested_item.get_octet_string_owned(&[{deep_id}]),")
                                    elif deep_type.endswith('Enum'):
                                        deep_nested_assignments.append(f"                                                {deep_rust_name}: deep_nested_item.get_int(&[{deep_id}]).map(|v| v as u8),")
                                    elif deep_type == 'list' and deep_entry_type:
                                        # Handle list fields in deeply nested structs
                                        if deep_entry_type.endswith('Enum'):
                                            # List of enums
                                            deep_nested_assignments.append(f'''                                                {deep_rust_name}: {{
                                                if let Some(tlv::TlvItemValue::List(l)) = deep_nested_item.get(&[{deep_id}]) {{
                                                    let items: Vec<u8> = l.iter().filter_map(|e| {{
                                                        if let tlv::TlvItemValue::Int(v) = &e.value {{
                                                            Some(*v as u8)
                                                        }} else {{
                                                            None
                                                        }}
                                                    }}).collect();
                                                    Some(items)
                                                }} else {{
                                                    None
                                                }}
                                            }},''')
                                        else:
                                            # Other list types
                                            rust_type = MatterType.get_rust_type(deep_entry_type)
                                            cast_expr = "*v" if rust_type == "u64" else f"*v as {rust_type}"
                                            deep_nested_assignments.append(f'''                                                {deep_rust_name}: {{
                                                if let Some(tlv::TlvItemValue::List(l)) = deep_nested_item.get(&[{deep_id}]) {{
                                                    let items: Vec<{rust_type}> = l.iter().filter_map(|e| {{
                                                        if let tlv::TlvItemValue::Int(v) = &e.value {{
                                                            Some({cast_expr})
                                                        }} else {{
                                                            None
                                                        }}
                                                    }}).collect();
                                                    Some(items)
                                                }} else {{
                                                    None
                                                }}
                                            }},''')
                                    else:
                                        deep_nested_assignments.append(f"                                                {deep_rust_name}: deep_nested_item.get_int(&[{deep_id}]).map(|v| v as u8),")
                                
                                deep_nested_assignments_str = "\n".join(deep_nested_assignments)
                                
                                nested_assignments.append(f'''                                {nested_rust_name}: {{
                                    if let Some(tlv::TlvItemValue::List(_)) = nested_item.get(&[{nested_id}]) {{
                                        if let Some(deep_nested_tlv) = nested_item.get(&[{nested_id}]) {{
                                            let deep_nested_item = tlv::TlvItem {{ tag: {nested_id}, value: deep_nested_tlv.clone() }};
                                            Some({deep_nested_struct_name} {{
{deep_nested_assignments_str}
                                            }})
                                        }} else {{
                                            None
                                        }}
                                    }} else {{
                                        None
                                    }}
                                }},''')
                            else:
                                nested_assignments.append(f"                                {nested_rust_name}: nested_item.get_int(&[{nested_id}]).map(|v| v as u8),")
                        
                        nested_assignments_str = "\n".join(nested_assignments)
                        
                        field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(tlv::TlvItemValue::List(_)) = item.get(&[{field_id}]) {{
                        if let Some(nested_tlv) = item.get(&[{field_id}]) {{
                            let nested_item = tlv::TlvItem {{ tag: {field_id}, value: nested_tlv.clone() }};
                            Some({nested_struct_name} {{
{nested_assignments_str}
                            }})
                        }} else {{
                            None
                        }}
                    }} else {{
                        None
                    }}
                }},''')
                    else:
                        # Default to treating as integer
                        field_assignments.append(f"                {rust_field_name}: item.get_int(&[{field_id}]).map(|v| v as u8),")
                
                assignments_str = "\n".join(field_assignments)
                
                decode_logic = f'''    let mut res = Vec::new();
    if let tlv::TlvItemValue::List(v) = inp {{
        for item in v {{
            res.push({struct_name} {{
{assignments_str}
            }});
        }}
    }}
    Ok(res)'''
            elif self.entry_type:
                # Generate list decoder based on entry type
                tlv_type = MatterType.get_tlv_type(self.entry_type)
                if tlv_type == "String":
                    decode_logic = '''    let mut res = Vec::new();
    if let tlv::TlvItemValue::List(v) = inp {
        for item in v {
            if let tlv::TlvItemValue::String(s) = &item.value {
                res.push(s.clone());
            }
        }
    }
    Ok(res)'''
                elif tlv_type.startswith("UInt"):
                    rust_type = MatterType.get_rust_type(self.entry_type)
                    decode_logic = f'''    let mut res = Vec::new();
    if let tlv::TlvItemValue::List(v) = inp {{
        for item in v {{
            if let tlv::TlvItemValue::Int(i) = &item.value {{
                res.push(*i as {rust_type});
            }}
        }}
    }}
    Ok(res)'''
                elif tlv_type == "Bool":
                    decode_logic = '''    let mut res = Vec::new();
    if let tlv::TlvItemValue::List(v) = inp {
        for item in v {
            if let tlv::TlvItemValue::Bool(b) = &item.value {
                res.push(*b);
            }
        }
    }
    Ok(res)'''
                elif tlv_type == "OctetString":
                    decode_logic = '''    let mut res = Vec::new();
    if let tlv::TlvItemValue::List(v) = inp {
        for item in v {
            if let tlv::TlvItemValue::OctetString(o) = &item.value {
                res.push(o.clone());
            }
        }
    }
    Ok(res)'''
                else:
                    # Default fallback
                    decode_logic = '''    let mut res = Vec::new();
    if let tlv::TlvItemValue::List(v) = inp {
        for item in v {
            // TODO: Handle custom struct type decoding
            res.push(Default::default());
        }
    }
    Ok(res)'''
            else:
                # Generic list decoder
                decode_logic = '''    let mut res = Vec::new();
    if let tlv::TlvItemValue::List(v) = inp {
        for item in v {
            if let tlv::TlvItemValue::String(s) = &item.value {
                res.push(s.clone());
            }
        }
    }
    Ok(res)'''
        else:
            # Single value decoder
            # Initialize tlv_type for all paths
            tlv_type = MatterType.get_tlv_type(self.attr_type)
            
            # Check if this is a custom struct type
            if structs and self.attr_type in structs:
                # Handle custom struct decoding
                struct = structs[self.attr_type]
                struct_name = struct.get_rust_struct_name()
                
                # Generate field assignments for the struct
                field_assignments = []
                for field_id, field_name, field_type, entry_type in struct.fields:
                    rust_field_name = convert_to_snake_case(field_name)
                    rust_field_name = escape_rust_keyword(rust_field_name)  # Escape Rust keywords
                    
                    if field_type == 'list' and entry_type:
                        # Handle list fields within struct
                        if entry_type.endswith('Struct') and structs and entry_type in structs:
                            # Custom struct list - generate proper decoding
                            target_struct = structs[entry_type]
                            struct_rust_name = target_struct.get_rust_struct_name()
                            
                            # Generate nested field assignments for the target struct
                            nested_assignments = []
                            for nested_id, nested_name, nested_type, nested_entry_type in target_struct.fields:
                                nested_rust_name = convert_to_snake_case(nested_name)
                                nested_rust_name = escape_rust_keyword(nested_rust_name)
                                
                                if is_numeric_or_id_type(nested_type):
                                    nested_assignments.append(build_nested_numeric_assignment(nested_rust_name, nested_id, nested_type))
                                elif nested_type == 'string':
                                    nested_assignments.append(f"                                {nested_rust_name}: list_item.get_string_owned(&[{nested_id}]),")
                                elif nested_type == 'bool':
                                    nested_assignments.append(f"                                {nested_rust_name}: list_item.get_bool(&[{nested_id}]),")
                                elif nested_type == 'octstr':
                                    nested_assignments.append(f"                                {nested_rust_name}: list_item.get_octet_string_owned(&[{nested_id}]),")
                                elif nested_type == 'list' and nested_entry_type:
                                    # Handle nested list fields with custom struct entries
                                    if nested_entry_type.endswith('Struct') and structs and nested_entry_type in structs:
                                        target_nested_struct = structs[nested_entry_type]
                                        nested_struct_rust_name = target_nested_struct.get_rust_struct_name()
                                        
                                        # Generate nested assignments for the nested struct
                                        nested_nested_assignments = []
                                        for nn_id, nn_name, nn_type, nn_entry_type in target_nested_struct.fields:
                                            nn_rust_name = convert_to_snake_case(nn_name)
                                            nn_rust_name = escape_rust_keyword(nn_rust_name)
                                            
                                            if is_numeric_or_id_type(nn_type):
                                                nested_nested_assignments.append(build_nested_numeric_assignment(nn_rust_name, nn_id, nn_type, "nested_item"))
                                            elif nn_type == 'string':
                                                nested_nested_assignments.append(f"                                        {nn_rust_name}: nested_item.get_string_owned(&[{nn_id}]),")
                                            elif nn_type == 'bool':
                                                nested_nested_assignments.append(f"                                        {nn_rust_name}: nested_item.get_bool(&[{nn_id}]),")
                                            elif nn_type == 'octstr':
                                                nested_nested_assignments.append(f"                                        {nn_rust_name}: nested_item.get_octet_string_owned(&[{nn_id}]),")
                                            else:
                                                nested_nested_assignments.append(f"                                        {nn_rust_name}: nested_item.get_int(&[{nn_id}]).map(|v| v as u8),")
                                        
                                        nested_nested_str = "\n".join(nested_nested_assignments)
                                        nested_assignments.append(f'''                                {nested_rust_name}: {{
                                    if let Some(tlv::TlvItemValue::List(nested_l)) = list_item.get(&[{nested_id}]) {{
                                        let mut nested_items = Vec::new();
                                        for nested_item in nested_l {{
                                            nested_items.push({nested_struct_rust_name} {{
{nested_nested_str}
                                            }});
                                        }}
                                        Some(nested_items)
                                    }} else {{
                                        None
                                    }}
                                }},''')
                                    else:
                                        nested_assignments.append(f"                                {nested_rust_name}: None, // TODO: Implement {nested_entry_type} nested list")
                                else:
                                    nested_assignments.append(f"                                {nested_rust_name}: list_item.get_int(&[{nested_id}]).map(|v| v as u8),")
                            
                            nested_assignments_str = "\n".join(nested_assignments)
                            
                            field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(tlv::TlvItemValue::List(l)) = item.get(&[{field_id}]) {{
                        let mut items = Vec::new();
                        for list_item in l {{
                            items.push({struct_rust_name} {{
{nested_assignments_str}
                            }});
                        }}
                        Some(items)
                    }} else {{
                        None
                    }}
                }},''')
                        elif entry_type.endswith('Struct'):
                            # Custom struct without definition
                            field_assignments.append(f"                {rust_field_name}: None, // TODO: Implement {entry_type} list decoding")
                        else:
                            # Primitive type list
                            rust_type = MatterType.get_rust_type(entry_type)
                            if entry_type == 'string':
                                field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(tlv::TlvItemValue::List(l)) = item.get(&[{field_id}]) {{
                        let items: Vec<{rust_type}> = l.iter().filter_map(|e| {{
                            if let tlv::TlvItemValue::String(v) = &e.value {{
                                Some(v.clone())
                            }} else {{
                                None
                            }}
                        }}).collect();
                        Some(items)
                    }} else {{
                        None
                    }}
                }},''')
                            elif entry_type == 'octstr':
                                field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(tlv::TlvItemValue::List(l)) = item.get(&[{field_id}]) {{
                        let items: Vec<{rust_type}> = l.iter().filter_map(|e| {{
                            if let tlv::TlvItemValue::OctetString(v) = &e.value {{
                                Some(v.clone())
                            }} else {{
                                None
                            }}
                        }}).collect();
                        Some(items)
                    }} else {{
                        None
                    }}
                }},''')
                            elif entry_type == 'bool':
                                field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(tlv::TlvItemValue::List(l)) = item.get(&[{field_id}]) {{
                        let items: Vec<{rust_type}> = l.iter().filter_map(|e| {{
                            if let tlv::TlvItemValue::Bool(v) = &e.value {{
                                Some(*v)
                            }} else {{
                                None
                            }}
                        }}).collect();
                        Some(items)
                    }} else {{
                        None
                    }}
                }},''')
                            else:
                                # Numeric types
                                cast_expr = "*v" if rust_type == "u64" else f"*v as {rust_type}"
                                field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(tlv::TlvItemValue::List(l)) = item.get(&[{field_id}]) {{
                        let items: Vec<{rust_type}> = l.iter().filter_map(|e| {{
                            if let tlv::TlvItemValue::Int(v) = &e.value {{
                                Some({cast_expr})
                            }} else {{
                                None
                            }}
                        }}).collect();
                        Some(items)
                    }} else {{
                        None
                    }}
                }},''')
                    elif is_numeric_or_id_type(field_type):
                        field_assignments.append(build_numeric_field_assignment(rust_field_name, field_id, field_type))
                    elif field_type == 'string':
                        field_assignments.append(f"                {rust_field_name}: item.get_string_owned(&[{field_id}]),")
                    elif field_type == 'bool':
                        field_assignments.append(f"                {rust_field_name}: item.get_bool(&[{field_id}]),")
                    elif field_type == 'octstr':
                        field_assignments.append(f"                {rust_field_name}: item.get_octet_string_owned(&[{field_id}]),")
                    elif field_type.endswith('Enum'):
                        # Handle enum fields as integers
                        field_assignments.append(f"                {rust_field_name}: item.get_int(&[{field_id}]).map(|v| v as u8),")
                    elif field_type.endswith('Struct') and structs and field_type in structs:
                        # Handle nested struct fields
                        nested_struct = structs[field_type]
                        nested_struct_name = nested_struct.get_rust_struct_name()
                        
                        # Generate nested field assignments for the nested struct
                        nested_assignments = []
                        for nested_id, nested_name, nested_type, nested_entry_type in nested_struct.fields:
                            nested_rust_name = convert_to_snake_case(nested_name)
                            nested_rust_name = escape_rust_keyword(nested_rust_name)
                            
                            if is_numeric_or_id_type(nested_type):
                                nested_assignments.append(build_nested_numeric_assignment(nested_rust_name, nested_id, nested_type, "nested_item"))
                            elif nested_type == 'string':
                                nested_assignments.append(f"                                {nested_rust_name}: nested_item.get_string_owned(&[{nested_id}]),")
                            elif nested_type == 'bool':
                                nested_assignments.append(f"                                {nested_rust_name}: nested_item.get_bool(&[{nested_id}]),")
                            elif nested_type == 'octstr':
                                nested_assignments.append(f"                                {nested_rust_name}: nested_item.get_octet_string_owned(&[{nested_id}]),")
                            elif nested_type.endswith('Enum'):
                                nested_assignments.append(f"                                {nested_rust_name}: nested_item.get_int(&[{nested_id}]).map(|v| v as u8),")
                            elif nested_type == 'list' and nested_entry_type:
                                # Handle list fields in nested structs (single-struct decode path)
                                if nested_entry_type.endswith('Enum'):
                                    # List of enums (like CharacteristicEnum)
                                    nested_assignments.append(f'''                                {nested_rust_name}: {{
                                    if let Some(tlv::TlvItemValue::List(l)) = nested_item.get(&[{nested_id}]) {{
                                        let items: Vec<u8> = l.iter().filter_map(|e| {{
                                            if let tlv::TlvItemValue::Int(v) = &e.value {{
                                                Some(*v as u8)
                                            }} else {{
                                                None
                                            }}
                                        }}).collect();
                                        Some(items)
                                    }} else {{
                                        None
                                    }}
                                }},''')
                                else:
                                    # Other list types
                                    rust_type = MatterType.get_rust_type(nested_entry_type)
                                    cast_expr = "*v" if rust_type == "u64" else f"*v as {rust_type}"
                                    nested_assignments.append(f'''                                {nested_rust_name}: {{
                                    if let Some(tlv::TlvItemValue::List(l)) = nested_item.get(&[{nested_id}]) {{
                                        let items: Vec<{rust_type}> = l.iter().filter_map(|e| {{
                                            if let tlv::TlvItemValue::Int(v) = &e.value {{
                                                Some({cast_expr})
                                            }} else {{
                                                None
                                            }}
                                        }}).collect();
                                        Some(items)
                                    }} else {{
                                        None
                                    }}
                                }},''')
                            else:
                                nested_assignments.append(f"                                {nested_rust_name}: nested_item.get_int(&[{nested_id}]).map(|v| v as u8),")
                        
                        nested_assignments_str = "\n".join(nested_assignments)
                        
                        field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(tlv::TlvItemValue::List(_)) = item.get(&[{field_id}]) {{
                        if let Some(nested_tlv) = item.get(&[{field_id}]) {{
                            let nested_item = tlv::TlvItem {{ tag: {field_id}, value: nested_tlv.clone() }};
                            Some({nested_struct_name} {{
{nested_assignments_str}
                            }})
                        }} else {{
                            None
                        }}
                    }} else {{
                        None
                    }}
                }},''')
                    else:
                        # Default to treating as integer
                        field_assignments.append(f"                {rust_field_name}: item.get_int(&[{field_id}]).map(|v| v as u8),")
                
                assignments_str = "\n".join(field_assignments)
                
                if self.nullable:
                    # For nullable structs, handle null values and wrap result in Some()
                    decode_logic = f'''    if let tlv::TlvItemValue::List(_fields) = inp {{
        // Struct with fields
        let item = tlv::TlvItem {{ tag: 0, value: inp.clone() }};
        Ok(Some({struct_name} {{
{assignments_str}
        }}))
    //}} else if let tlv::TlvItemValue::Null = inp {{
    //    // Null value for nullable struct
    //    Ok(None)
    }} else {{
    Ok(None)
    //    Err(anyhow::anyhow!("Expected struct fields or null"))
    }}'''
                else:
                    # For non-nullable structs
                    decode_logic = f'''    if let tlv::TlvItemValue::List(_fields) = inp {{
        // Struct with fields
        let item = tlv::TlvItem {{ tag: 0, value: inp.clone() }};
        Ok({struct_name} {{
{assignments_str}
        }})
    }} else {{
        Err(anyhow::anyhow!("Expected struct fields"))
    }}'''
            else:
                # For non-struct types, handle the decoding logic based on tlv_type
                if self.nullable:
                    # Handle nullable single values
                    if tlv_type == "String":
                        decode_logic = '''    if let tlv::TlvItemValue::String(v) = inp {
        Ok(Some(v.clone()))
    } else {
        Ok(None)
    }'''
                    elif tlv_type.startswith("UInt") or tlv_type.startswith("Int"):
                        rust_type = MatterType.get_rust_type(self.attr_type)
                        # Avoid unnecessary cast when target type is u64 (same as TlvItemValue::Int)
                        cast_expr = "*v" if rust_type == "u64" else f"*v as {rust_type}"
                        decode_logic = f'''    if let tlv::TlvItemValue::Int(v) = inp {{
        Ok(Some({cast_expr}))
    }} else {{
        Ok(None)
    }}'''
                    elif tlv_type == "Bool":
                        decode_logic = '''    if let tlv::TlvItemValue::Bool(v) = inp {
        Ok(Some(*v))
    } else {
        Ok(None)
    }'''
                    elif tlv_type == "OctetString":
                        decode_logic = '''    if let tlv::TlvItemValue::OctetString(v) = inp {
        Ok(Some(v.clone()))
    } else {
        Ok(None)
    }'''
                    else:
                        decode_logic = '''    // TODO: Handle nullable custom type decoding
    Ok(None)'''
                else:
                    # Non-nullable single values
                    if tlv_type == "String":
                        decode_logic = '''    if let tlv::TlvItemValue::String(v) = inp {
        Ok(v.clone())
    } else {
        Err(anyhow::anyhow!("Expected String"))
    }'''
                    elif tlv_type.startswith("UInt") or tlv_type.startswith("Int"):
                        rust_type = MatterType.get_rust_type(self.attr_type)
                        # Avoid unnecessary cast when target type is u64 (same as TlvItemValue::Int)
                        cast_expr = "*v" if rust_type == "u64" else f"*v as {rust_type}"
                        decode_logic = f'''    if let tlv::TlvItemValue::Int(v) = inp {{
        Ok({cast_expr})
    }} else {{
        Err(anyhow::anyhow!("Expected Integer"))
    }}'''
                    elif tlv_type == "Bool":
                        decode_logic = '''    if let tlv::TlvItemValue::Bool(v) = inp {
        Ok(*v)
    } else {
        Err(anyhow::anyhow!("Expected Bool"))
    }'''
                    elif tlv_type == "OctetString":
                        decode_logic = '''    if let tlv::TlvItemValue::OctetString(v) = inp {
        Ok(v.clone())
    } else {
        Err(anyhow::anyhow!("Expected OctetString"))
    }'''
                    else:
                        decode_logic = '''    // TODO: Handle custom type decoding
    Err(anyhow::anyhow!("Unsupported type"))'''
        
        return f'''/// Decode {self.name} attribute ({clean_id})
pub fn {func_name}(inp: &tlv::TlvItemValue) -> anyhow::Result<{return_type}> {{
{decode_logic}
}}'''


class CommandField:
    """Represents a field in a Matter command."""
    
    def __init__(self, id: int, name: str, field_type: str, default: Optional[str] = None, 
                 nullable: bool = False, mandatory: bool = True, entry_type: Optional[str] = None):
        self.id = id
        self.name = name
        self.field_type = field_type
        self.default = default
        self.nullable = nullable
        self.mandatory = mandatory
        self.entry_type = entry_type  # For list types
        self.is_list = field_type == 'list'
    
    def get_rust_param_name(self) -> str:
        """Convert field name to snake_case Rust parameter name."""
        return escape_rust_keyword(convert_to_snake_case(self.name))
    
    def get_tlv_encoding(self, param_name: str) -> str:
        """Generate TLV encoding line for this field."""
        if self.is_list:
            # For list types, we need to encode as array
            return f"        ({self.id}, tlv::TlvItemValueEnc::StructAnon({param_name}.into_iter().map(|v| (0, tlv::TlvItemValueEnc::UInt8(v)).into()).collect())).into(),"
        
        tlv_type = MatterType.get_tlv_type(self.field_type)
        
        if self.nullable:
            # Handle nullable fields
            if self.default and self.default.lower() in ['null', 'none']:
                return f"        ({self.id}, tlv::TlvItemValueEnc::{tlv_type}({param_name}.unwrap_or_default())).into(),"
            else:
                # Generate appropriate default value based on field type
                default_value = self._get_default_value()
                return f"        ({self.id}, tlv::TlvItemValueEnc::{tlv_type}({param_name}.unwrap_or({default_value}))).into(),"
        else:
            return f"        ({self.id}, tlv::TlvItemValueEnc::{tlv_type}({param_name})).into(),"
    
    def _get_default_value(self) -> str:
        """Generate appropriate default value based on field type and XML default attribute."""
        if not self.default:
            # No default specified, use type-appropriate fallback
            if self.field_type == 'string':
                return '"".to_string()'
            elif self.field_type == 'octstr':
                return 'vec![]'
            elif self.field_type == 'bool':
                return 'false'
            else:
                return '0'
        
        # Handle specific default values from XML
        if self.field_type == 'string':
            if self.default.lower() == 'empty':
                return '"".to_string()'
            else:
                # Use the provided default value as a string literal
                return f'"{self.default}".to_string()'
        elif self.field_type == 'octstr':
            if self.default.lower() == 'empty':
                return 'vec![]'
            else:
                # For octstr with specific default, might need more complex handling
                return 'vec![]'  # Safe fallback
        elif self.field_type == 'bool':
            return self.default.lower()
        elif 'enum' in self.field_type.lower():
            # For enum types, we need numeric values, not names
            # Try to extract numeric value or use 0 as fallback
            if self.default.isdigit():
                return self.default
            else:
                return '0'  # Safe fallback for enum names
        else:
            # For numeric types, use the default value directly
            return self.default


class MatterCommand:
    """Represents a Matter command with its fields."""
    
    def __init__(self, id: str, name: str, direction: str):
        self.id = id
        self.name = name
        self.direction = direction
        self.fields: List[CommandField] = []
    
    def add_field(self, field: CommandField):
        """Add a field to this command."""
        self.fields.append(field)
    
    def get_rust_function_name(self) -> str:
        """Convert command name to snake_case Rust function name."""
        return f"encode_{escape_rust_keyword(convert_to_snake_case(self.name))}"
    
    def generate_rust_function(self) -> str:
        """Generate complete Rust function for encoding this command."""
        func_name = self.get_rust_function_name()
        
        # Generate function parameters
        params = []
        for field in self.fields:
            param_name = field.get_rust_param_name()
            rust_type = MatterType.get_rust_type(field.field_type, field.is_list)
            
            if field.nullable:
                rust_type = f"Option<{rust_type}>"
            
            params.append(f"{param_name}: {rust_type}")
        
        param_str = ", ".join(params) if params else ""
        
        # Generate TLV encoding
        tlv_fields = []
        for field in self.fields:
            param_name = field.get_rust_param_name()
            tlv_fields.append(field.get_tlv_encoding(param_name))
        
        tlv_fields_str = "\n".join(tlv_fields) if tlv_fields else "        // No fields"
        
        # Clean up command ID format
        clean_id = self.id.replace('0x0x', '0x') if self.id.startswith('0x0x') else self.id
        
        # Generate function
        function = f'''/// Encode {self.name} command ({clean_id})
pub fn {func_name}({param_str}) -> anyhow::Result<Vec<u8>> {{
    let tlv = tlv::TlvItemEnc {{
        tag: 0,
        value: tlv::TlvItemValueEnc::StructInvisible(vec![
{tlv_fields_str}
        ]),
    }};
    Ok(tlv.encode()?)
}}'''
        
        return function





class ClusterParser:
    """Parses Matter cluster XML files."""
    
    def __init__(self, xml_file: str):
        self.xml_file = xml_file
        self.tree = ET.parse(xml_file)
        self.root = self.tree.getroot()
        self.cluster_name = self.root.get('name', 'Unknown')
        self.cluster_id = self.root.get('id', '0x0000')
        
    def parse_commands(self) -> List[MatterCommand]:
        """Parse all commands from the XML."""
        commands = []
        
        commands_elem = self.root.find('commands')
        if commands_elem is None:
            return commands
        
        for cmd_elem in commands_elem.findall('command'):
            cmd_id = cmd_elem.get('id', '0x00')
            cmd_name = cmd_elem.get('name', 'Unknown')
            cmd_direction = cmd_elem.get('direction', 'commandToServer')
            
            # Only process commands to server (client-to-server)
            if cmd_direction != 'commandToServer':
                continue
                
            command = MatterCommand(cmd_id, cmd_name, cmd_direction)
            
            # Parse command fields
            for field_elem in cmd_elem.findall('field'):
                field_id = int(field_elem.get('id', '0'))
                field_name = field_elem.get('name', 'Unknown')
                field_type = field_elem.get('type', 'uint8')
                field_default = field_elem.get('default')
                
                # Check for entry type (for list fields)
                entry_elem = field_elem.find('entry')
                entry_type = None
                if entry_elem is not None:
                    entry_type = entry_elem.get('type')

                
                # Check if field is nullable
                quality_elem = field_elem.find('quality')
                nullable = False
                if quality_elem is not None:
                    nullable = quality_elem.get('nullable', 'false').lower() == 'true'
                
                # Check if field is mandatory
                mandatory_elem = field_elem.find('mandatoryConform')
                mandatory = mandatory_elem is not None
                
                field = CommandField(field_id, field_name, field_type, field_default, nullable, mandatory, entry_type)
                command.add_field(field)
            
            # Handle commands with similar structure (like *WithOnOff commands)
            # If a command has no fields but is similar to another, inherit fields
            if not command.fields and cmd_name.endswith('WithOnOff'):
                base_name = cmd_name.replace('WithOnOff', '')
                # Look for the base command to inherit fields
                for base_cmd_elem in commands_elem.findall('command'):
                    if base_cmd_elem.get('name') == base_name:
                        # Copy fields from base command
                        for field_elem in base_cmd_elem.findall('field'):
                            field_id = int(field_elem.get('id', '0'))
                            field_name = field_elem.get('name', 'Unknown')
                            field_type = field_elem.get('type', 'uint8')
                            field_default = field_elem.get('default')
                            
                            entry_elem = field_elem.find('entry')
                            entry_type = None
                            if entry_elem is not None:
                                entry_type = entry_elem.get('type')
                            
                            quality_elem = field_elem.find('quality')
                            nullable = False
                            if quality_elem is not None:
                                nullable = quality_elem.get('nullable', 'false').lower() == 'true'
                            
                            mandatory_elem = field_elem.find('mandatoryConform')
                            mandatory = mandatory_elem is not None
                            
                            field = CommandField(field_id, field_name, field_type, field_default, nullable, mandatory, entry_type)
                            command.add_field(field)
                        break
            
            commands.append(command)
        
        return commands
    
    def parse_attributes(self) -> List[AttributeField]:
        """Parse all attributes from the XML."""
        attributes = []
        
        attributes_elem = self.root.find('attributes')
        if attributes_elem is None:
            return attributes
        
        for attr_elem in attributes_elem.findall('attribute'):
            attr_id = attr_elem.get('id', '0x0000')
            attr_name = attr_elem.get('name', 'Unknown')
            attr_type = attr_elem.get('type', 'uint8')
            attr_default = attr_elem.get('default')
            
            # Check for entry type (for list attributes)
            entry_elem = attr_elem.find('entry')
            entry_type = None
            if entry_elem is not None:
                entry_type = entry_elem.get('type')
            
            # Check if attribute is nullable
            quality_elem = attr_elem.find('quality')
            nullable = False
            if quality_elem is not None:
                nullable = quality_elem.get('nullable', 'false').lower() == 'true'
            
            attribute = AttributeField(attr_id, attr_name, attr_type, attr_default, nullable, entry_type)
            attributes.append(attribute)
        
        return attributes
    
    def parse_structs(self) -> Dict[str, MatterStruct]:
        """Parse all struct definitions from the XML."""
        structs = {}
        
        data_types_elem = self.root.find('dataTypes')
        if data_types_elem is None:
            return structs
        
        for struct_elem in data_types_elem.findall('struct'):
            struct_name = struct_elem.get('name', 'Unknown')
            struct = MatterStruct(struct_name)
            
            # Parse struct fields
            for field_elem in struct_elem.findall('field'):
                field_id = int(field_elem.get('id', '0'))
                field_name = field_elem.get('name', 'Unknown')
                field_type = field_elem.get('type', 'uint8')
                
                # Check for entry type (for list fields)
                entry_elem = field_elem.find('entry')
                entry_type = None
                if entry_elem is not None:
                    entry_type = entry_elem.get('type')

                
                struct.add_field(field_id, field_name, field_type, entry_type)
            
            structs[struct_name] = struct
        
        return structs


def generate_json_dispatcher_function(cluster_id: str, attributes: List[AttributeField], structs: Dict[str, MatterStruct]) -> str:
    """Generate a JSON dispatcher function that routes attribute decoding based on attribute ID."""
    if not attributes:
        return ""
    
    # Clean up cluster ID format
    clean_cluster_id = cluster_id.replace('0x0x', '0x') if cluster_id.startswith('0x0x') else cluster_id
    
    # Generate match arms for each unique attribute (deduplicate by ID)
    match_arms = []
    seen_ids = set()
    for attribute in attributes:
        # Clean up attribute ID format
        clean_attr_id = attribute.id.replace('0x0x', '0x') if attribute.id.startswith('0x0x') else attribute.id
        
        # Skip duplicates
        if clean_attr_id in seen_ids:
            continue
        seen_ids.add(clean_attr_id)
        
        func_name = attribute.get_rust_function_name()
        
        match_arm = f'''        {clean_attr_id} => {{
            match {func_name}(tlv_value) {{
                Ok(value) => serde_json::to_string(&value).unwrap_or_else(|_| "null".to_string()),
                Err(e) => format!("{{{{\\\"error\\\": \\\"{{}}\\\"}}}}", e),
            }}
        }}'''
        match_arms.append(match_arm)
    
    match_arms_str = "\n".join(match_arms)
    
    dispatcher_function = f'''
// JSON dispatcher function

/// Decode attribute value and return as JSON string
/// 
/// # Parameters
/// * `cluster_id` - The cluster identifier
/// * `attribute_id` - The attribute identifier
/// * `tlv_value` - The TLV value to decode
/// 
/// # Returns
/// JSON string representation of the decoded value or error
pub fn decode_attribute_json(cluster_id: u32, attribute_id: u32, tlv_value: &crate::tlv::TlvItemValue) -> String {{
    // Verify this is the correct cluster
    if cluster_id != {clean_cluster_id} {{
        return format!("{{{{\\\"error\\\": \\\"Invalid cluster ID. Expected {clean_cluster_id}, got {{}}\\\"}}}}", cluster_id);
    }}
    
    match attribute_id {{
{match_arms_str}
        _ => format!("{{{{\\\"error\\\": \\\"Unknown attribute ID: {{}}\\\"}}}}", attribute_id),
    }}
}}

'''
    
    return dispatcher_function


def generate_attribute_list_function(cluster_id: str, attributes: List[AttributeField]) -> str:
    """Generate a function that returns all attributes for this cluster as a list."""
    if not attributes:
        return ""
    
    # Clean up cluster ID format
    clean_cluster_id = cluster_id.replace('0x0x', '0x') if cluster_id.startswith('0x0x') else cluster_id
    
    # Generate attribute list entries
    attribute_entries = []
    seen_ids = set()
    
    for attribute in attributes:
        # Clean up attribute ID format
        clean_attr_id = attribute.id.replace('0x0x', '0x') if attribute.id.startswith('0x0x') else attribute.id
        
        # Skip duplicates
        if clean_attr_id in seen_ids:
            continue
        seen_ids.add(clean_attr_id)
        
        # Create attribute entry with ID and name
        attribute_entries.append(f'        ({clean_attr_id}, "{attribute.name}"),')
    entries_str = "\n".join(attribute_entries)
    
    function = f'''/// Get list of all attributes supported by this cluster
/// 
/// # Returns
/// Vector of tuples containing (attribute_id, attribute_name)
pub fn get_attribute_list() -> Vec<(u32, &'static str)> {{
    vec![
{entries_str}
    ]
}}

'''
    
    return function


def generate_rust_code(xml_file: str) -> str:
    """Generate Rust code for the given XML cluster file."""
    parser = ClusterParser(xml_file)
    commands = parser.parse_commands()
    attributes = parser.parse_attributes()
    structs = parser.parse_structs()
    
    # Add LocationDescriptorStruct only if needed by this cluster
    location_needed = False
    for attr in attributes:
        if attr.attr_type == 'LocationDescriptorStruct':
            location_needed = True
            break
    
    # Also check if any struct field references LocationDescriptorStruct
    if not location_needed:
        for struct in structs.values():
            for field_id, field_name, field_type, entry_type in struct.fields:
                if field_type == 'LocationDescriptorStruct' or entry_type == 'LocationDescriptorStruct':
                    location_needed = True
                    break
            if location_needed:
                break
    
    # Add hardcoded LocationDescriptorStruct if needed and not already defined
    if location_needed and 'LocationDescriptorStruct' not in structs:
        location_struct = MatterStruct('LocationDescriptorStruct')
        location_struct.add_field(0, 'LocationName', 'string')
        location_struct.add_field(1, 'FloorNumber', 'uint16')
        location_struct.add_field(2, 'AreaType', 'uint8')
        structs['LocationDescriptorStruct'] = location_struct
    
    # Generate header
    cluster_name_snake = parser.cluster_name.lower().replace(' ', '_').replace('-', '_')
    
    # Generate imports based on what we're generating
    imports = ""
    # Check if we have commands with fields (not field-less commands)
    commands_with_fields = [cmd for cmd in commands if cmd.fields]
    if commands_with_fields or attributes or structs:
        imports += "use crate::tlv;\n"
    if commands_with_fields or attributes:
        imports += "use anyhow;\n"
    if attributes:
        imports += "use serde_json;\n"
    
    code = f'''//! Generated Matter TLV encoders and decoders for {parser.cluster_name}
//! Cluster ID: {parser.cluster_id}
//! 
//! This file is automatically generated from {os.path.basename(xml_file)}

{imports}

'''
    
    # Generate struct definitions
    if structs:
        code += "// Struct definitions\n\n"
        for struct in structs.values():
            code += struct.generate_rust_struct(structs) + "\n\n"
    
    # Generate command encoders
    if commands:
        code += "// Command encoders\n\n"
        generated_functions = set()
        for command in commands:
            # Skip commands with no fields - they don't need encoders
            if not command.fields:
                continue
                
            func_name = command.get_rust_function_name()
            if func_name not in generated_functions:
                code += command.generate_rust_function() + "\n\n"
                generated_functions.add(func_name)
    
    # Generate attribute decoders
    if attributes:
        code += "// Attribute decoders\n\n"
        generated_functions = set()
        for attribute in attributes:
            func_name = attribute.get_rust_function_name()
            if func_name not in generated_functions:
                code += attribute.generate_decode_function(structs) + "\n\n"
                generated_functions.add(func_name)
        
        # Generate JSON dispatcher function
        code += generate_json_dispatcher_function(parser.cluster_id, attributes, structs)
        
        # Generate attribute list function
        code += generate_attribute_list_function(parser.cluster_id, attributes)
    
    return code


def generate_rust_filename(xml_filename: str) -> str:
    """Generate Rust filename from XML filename."""
    # Remove .xml extension
    base_name = os.path.splitext(xml_filename)[0]
    
    # Use the improved snake_case conversion
    result = convert_to_snake_case(base_name)
    
    # Handle special characters that might remain
    result = re.sub(r'[^a-z0-9_]', '_', result)
    result = re.sub(r'_+', '_', result).strip('_')
    
    return f"{result}.rs"


def generate_module_name(rust_filename: str) -> str:
    """Generate valid Rust module name from filename."""
    # Remove .rs extension
    module_name = os.path.splitext(rust_filename)[0]
    
    # Ensure it starts with a letter or underscore
    if module_name and not (module_name[0].isalpha() or module_name[0] == '_'):
        module_name = f"cluster_{module_name}"
    
    return module_name


def get_cluster_id(root) -> str:
    """Extract cluster ID from XML root element."""
    return root.get('id', '0x0000')


def generate_main_dispatcher(cluster_info: List[Dict[str, str]]) -> str:
    """Generate the main decode_attribute_json dispatcher function."""
    
    # Build match arms for each cluster that has attributes, avoiding duplicates
    seen_cluster_ids = set()
    match_arms = []
    
    for info in sorted(cluster_info, key=lambda x: x['cluster_id']):
        if info['has_attributes'] and info['cluster_id'] not in seen_cluster_ids:
            match_arms.append(f"        {info['cluster_id']} => {info['module_name']}::decode_attribute_json(cluster_id, attribute_id, tlv_value),")
            seen_cluster_ids.add(info['cluster_id'])
    match_arms_str = '\n'.join(match_arms)
    
    dispatcher_function = f'''
/// Main dispatcher function for decoding attributes to JSON
/// 
/// This function routes to the appropriate cluster-specific decoder based on cluster ID.
/// 
/// # Parameters
/// * `cluster_id` - The cluster identifier
/// * `attribute_id` - The attribute identifier  
/// * `tlv_value` - The TLV value to decode
/// 
/// # Returns
/// JSON string representation of the decoded value or error message
pub fn decode_attribute_json(cluster_id: u32, attribute_id: u32, tlv_value: &crate::tlv::TlvItemValue) -> String {{
    match cluster_id {{
{match_arms_str}
        _ => format!("{{{{\\\"error\\\": \\\"Unsupported cluster ID: {{}}\\\"}}}}", cluster_id),
    }}
}}
'''
    
    return dispatcher_function


def generate_main_attribute_list_dispatcher(cluster_info: List[Dict[str, str]]) -> str:
    """Generate the main get_attribute_list dispatcher function."""
    
    # Build match arms for each cluster that has attributes, avoiding duplicates
    seen_cluster_ids = set()
    match_arms = []
    
    for info in sorted(cluster_info, key=lambda x: x['cluster_id']):
        if info['has_attributes'] and info['cluster_id'] not in seen_cluster_ids:
            match_arms.append(f"        {info['cluster_id']} => {info['module_name']}::get_attribute_list(),")
            seen_cluster_ids.add(info['cluster_id'])
    match_arms_str = '\n'.join(match_arms)
    
    dispatcher_function = f'''
/// Main dispatcher function for getting attribute lists
/// 
/// This function routes to the appropriate cluster-specific attribute list based on cluster ID.
/// 
/// # Parameters
/// * `cluster_id` - The cluster identifier
/// 
/// # Returns
/// Vector of tuples containing (attribute_id, attribute_name) or empty vector if unsupported
pub fn get_attribute_list(cluster_id: u32) -> Vec<(u32, &'static str)> {{
    match cluster_id {{
{match_arms_str}
        _ => vec![],
    }}
}}
'''
    
    return dispatcher_function


def generate_mod_file(output_dir: str, rust_files: List[str], cluster_info: List[Dict[str, str]]) -> None:
    """Generate a mod.rs file that includes all generated modules."""
    mod_file_path = os.path.join(output_dir, "mod.rs")
    
    with open(mod_file_path, 'w') as f:
        f.write("//! Generated Matter cluster TLV encoders\n")
        f.write("//! \n")
        f.write("//! This file is automatically generated.\n\n")
        
        # Generate module declarations
        for rust_file in sorted(rust_files):
            module_name = generate_module_name(rust_file)
            f.write(f"pub mod {module_name};\n")
        
        # Add main dispatcher function
        f.write("\n")
        f.write(generate_main_dispatcher(cluster_info))
        
        # Add main attribute list dispatcher function
        f.write("\n")
        f.write(generate_main_attribute_list_dispatcher(cluster_info))
    
    print(f"  ✓ Generated mod.rs with {len(rust_files)} modules and main dispatchers")


def process_xml_files(xml_dir: str, output_dir: str) -> None:
    """Process all XML files in the given directory."""
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Find all XML files in the directory
    xml_pattern = os.path.join(xml_dir, "*.xml")
    xml_files = glob.glob(xml_pattern)
    
    if not xml_files:
        print(f"No XML files found in directory: {xml_dir}")
        return
    
    print(f"Found {len(xml_files)} XML files in {xml_dir}")
    
    processed_count = 0
    failed_count = 0
    generated_rust_files = []
    cluster_info = []
    
    for xml_file in sorted(xml_files):
        xml_filename = os.path.basename(xml_file)
        rust_filename = generate_rust_filename(xml_filename)
        output_file = os.path.join(output_dir, rust_filename)
        
        try:
            print(f"Processing {xml_filename} -> {rust_filename}")
            
            # Parse XML to get cluster information
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Extract cluster information
            cluster_id = get_cluster_id(root)
            module_name = generate_module_name(rust_filename)
            
            # Check if cluster has attributes
            attributes = root.findall(".//attribute")
            has_attributes = len(attributes) > 0
            
            cluster_info.append({
                'cluster_id': cluster_id,
                'module_name': module_name,
                'has_attributes': has_attributes,
                'xml_filename': xml_filename
            })
            
            rust_code = generate_rust_code(xml_file)
            
            with open(output_file, 'w') as f:
                f.write(rust_code)
            
            generated_rust_files.append(rust_filename)
            processed_count += 1
            print(f"  ✓ Generated {rust_filename}")
            
        except Exception as e:
            print(f"  ✗ Error processing {xml_filename}: {e}")
            failed_count += 1
    
    # Generate mod.rs file with main dispatcher
    if generated_rust_files:
        generate_mod_file(output_dir, generated_rust_files, cluster_info)
    
    print(f"\nProcessing complete:")
    print(f"  Successfully processed: {processed_count} files")
    print(f"  Failed: {failed_count} files")
    print(f"  Output directory: {output_dir}")


def main():
    """Main entry point."""
    if len(sys.argv) != 3:
        print("Usage: python generate.py <xml_directory> <output_directory>")
        print("")
        print("Examples:")
        print("  python generate.py ../xml ./generated")
        print("  python generate.py /path/to/xml/files /path/to/output")
        sys.exit(1)
    
    xml_dir = sys.argv[1]
    output_dir = sys.argv[2]
    
    if not os.path.exists(xml_dir):
        print(f"Error: XML directory '{xml_dir}' not found")
        sys.exit(1)
    
    if not os.path.isdir(xml_dir):
        print(f"Error: '{xml_dir}' is not a directory")
        sys.exit(1)
    
    try:
        process_xml_files(xml_dir, output_dir)
    
    except Exception as e:
        print(f"Error processing files: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
