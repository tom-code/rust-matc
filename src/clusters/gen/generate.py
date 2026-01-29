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


NUMERIC_OR_ID_TYPES = {
    'devtype-id', 'cluster-id', 'endpoint-no', 'node-id', 'vendor-id', 'epoch-s', 'epoch-us', 'elapsed-s', 'power-mW', 'energy-mWh', 'temperature', 'subject-id', 'attribute-id'
}

def is_numeric_or_id_type(t: str) -> bool:
    """Return True if the Matter type is numeric or a well-known ID type."""
    return t.startswith('uint') or t.startswith('int') or t in NUMERIC_OR_ID_TYPES

def build_numeric_field_assignment(var_name: str, field_id: int, matter_type: str, enums: Dict[str, 'MatterEnum'] = None, indent: str = '                ', item_var: str = 'item') -> str:
    """Generate Rust code snippet for assigning a numeric/ID field with proper casting."""
    rust_type = MatterType.get_rust_type(matter_type, enums=enums)
    if rust_type == 'u64':
        return f"{indent}{var_name}: {item_var}.get_int(&[{field_id}]),"
    else:
        return f"{indent}{var_name}: {item_var}.get_int(&[{field_id}]).map(|v| v as {rust_type}),"

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


def _generate_struct_field_assignments(struct_fields: List[Tuple[int, str, str, Optional[str]]], structs: Dict[str, 'MatterStruct'], enums: Dict[str, 'MatterEnum'], item_var: str) -> List[str]:
    """Generate Rust field assignments for a struct from a TLV item."""
    field_assignments = []
    for field_id, field_name, field_type, entry_type in struct_fields:
        rust_field_name = convert_to_snake_case(field_name)
        rust_field_name = escape_rust_keyword(rust_field_name)

        if field_type == 'list' and entry_type:
            if entry_type.endswith('Struct') and structs and entry_type in structs:
                target_struct = structs[entry_type]
                struct_rust_name = target_struct.get_rust_struct_name()
                nested_assignments_str = "\n".join(_generate_struct_field_assignments(target_struct.fields, structs, enums, "list_item"))
                field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(tlv::TlvItemValue::List(l)) = {item_var}.get(&[{field_id}]) {{
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
                field_assignments.append(f"                {rust_field_name}: None, // TODO: Implement {entry_type} list decoding")
            else:
                rust_type = MatterType.get_rust_type(entry_type, enums=enums)
                value_map = _generate_list_item_filter_expr(entry_type, enums=enums)

                field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(tlv::TlvItemValue::List(l)) = {item_var}.get(&[{field_id}]) {{
                        let items: Vec<{rust_type}> = l.iter().filter_map(|e| {{ {value_map} }}).collect();
                        Some(items)
                    }} else {{
                        None
                    }}
                }},''')
        elif is_numeric_or_id_type(field_type):
            field_assignments.append(build_numeric_field_assignment(rust_field_name, field_id, field_type, enums=enums, indent='                ', item_var=item_var))
        elif field_type == 'string':
            field_assignments.append(f"                {rust_field_name}: {item_var}.get_string_owned(&[{field_id}]),")
        elif field_type == 'bool':
            field_assignments.append(f"                {rust_field_name}: {item_var}.get_bool(&[{field_id}]),")
        elif field_type == 'octstr':
            field_assignments.append(f"                {rust_field_name}: {item_var}.get_octet_string_owned(&[{field_id}]),")
        elif field_type.endswith('Enum'):
            # Check if we have the enum definition
            if enums and field_type in enums:
                enum_name = enums[field_type].get_rust_enum_name()
                field_assignments.append(f"                {rust_field_name}: {item_var}.get_int(&[{field_id}]).and_then(|v| {enum_name}::from_u8(v as u8)),")
            else:
                # Fallback to u8 if enum not defined
                field_assignments.append(f"                {rust_field_name}: {item_var}.get_int(&[{field_id}]).map(|v| v as u8),")
        elif field_type.endswith('Struct') and structs and field_type in structs:
            nested_struct = structs[field_type]
            nested_struct_name = nested_struct.get_rust_struct_name()
            nested_assignments_str = "\n".join(_generate_struct_field_assignments(nested_struct.fields, structs, enums, "nested_item"))
            field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(nested_tlv) = {item_var}.get(&[{field_id}]) {{
                        if let tlv::TlvItemValue::List(_) = nested_tlv {{
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
            field_assignments.append(f"                {rust_field_name}: {item_var}.get_int(&[{field_id}]).map(|v| v as u8),")
    return field_assignments


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


def _get_value_cast_expr(value_var: str, matter_type: str, enums: Dict[str, 'MatterEnum'] = None) -> str:
    """Generate appropriate cast expression for a value based on its Matter type.

    Args:
        value_var: The variable name to cast (e.g., 'v', 'x', '*i')
        matter_type: The Matter type string
        enums: Dictionary of enum definitions

    Returns:
        A string expression for casting the value
    """
    if matter_type.endswith('Enum') and enums and matter_type in enums:
        return f'{value_var}.to_u8()'
    rust_type = MatterType.get_rust_type(matter_type, enums=enums)
    return value_var if rust_type == 'u64' else f'{value_var} as {rust_type}'


def _generate_list_item_filter_expr(entry_type: str, enums: Dict[str, 'MatterEnum'] = None) -> str:
    """Generate the filter_map expression for decoding a list item.

    Returns a string like: 'if let tlv::TlvItemValue::String(s) = &e.value { Some(s.clone()) } else { None }'
    """
    tlv_type = MatterType.get_tlv_type(entry_type)
    rust_type = MatterType.get_rust_type(entry_type, enums=enums)

    if tlv_type == "String":
        return 'if let tlv::TlvItemValue::String(v) = &e.value { Some(v.clone()) } else { None }'
    elif tlv_type == "Bool":
        return 'if let tlv::TlvItemValue::Bool(v) = &e.value { Some(*v) } else { None }'
    elif tlv_type == "OctetString":
        return 'if let tlv::TlvItemValue::OctetString(v) = &e.value { Some(v.clone()) } else { None }'
    elif tlv_type.startswith("UInt") or tlv_type.startswith("Int"):
        if entry_type.endswith('Enum') and enums and entry_type in enums:
            return f'if let tlv::TlvItemValue::Int(v) = &e.value {{ {rust_type}::from_u8(*v as u8) }} else {{ None }}'
        else:
            cast_expr = _get_value_cast_expr('*v', entry_type, enums)
            return f'if let tlv::TlvItemValue::Int(v) = &e.value {{ Some({cast_expr}) }} else {{ None }}'
    else:
        return 'None  // Unsupported type'


def _generate_list_decoder(entry_type: str, enums: Dict[str, 'MatterEnum'] = None) -> str:
    """Generate complete list decoder code for a given entry type.

    Args:
        entry_type: The type of items in the list
        enums: Dictionary of enum definitions

    Returns:
        String containing the complete decode_logic code block
    """
    tlv_type = MatterType.get_tlv_type(entry_type)
    rust_type = MatterType.get_rust_type(entry_type, enums=enums)

    if tlv_type == "String":
        return '''    let mut res = Vec::new();
    if let tlv::TlvItemValue::List(v) = inp {
        for item in v {
            if let tlv::TlvItemValue::String(s) = &item.value {
                res.push(s.clone());
            }
        }
    }
    Ok(res)'''
    elif tlv_type == "Bool":
        return '''    let mut res = Vec::new();
    if let tlv::TlvItemValue::List(v) = inp {
        for item in v {
            if let tlv::TlvItemValue::Bool(b) = &item.value {
                res.push(*b);
            }
        }
    }
    Ok(res)'''
    elif tlv_type == "OctetString":
        return '''    let mut res = Vec::new();
    if let tlv::TlvItemValue::List(v) = inp {
        for item in v {
            if let tlv::TlvItemValue::OctetString(o) = &item.value {
                res.push(o.clone());
            }
        }
    }
    Ok(res)'''
    elif tlv_type.startswith("UInt") or tlv_type.startswith("Int"):
        # Check if this is an enum type
        if entry_type.endswith('Enum') and enums and entry_type in enums:
            return f'''    let mut res = Vec::new();
    if let tlv::TlvItemValue::List(v) = inp {{
        for item in v {{
            if let tlv::TlvItemValue::Int(i) = &item.value {{
                if let Some(enum_val) = {rust_type}::from_u8(*i as u8) {{
                    res.push(enum_val);
                }}
            }}
        }}
    }}
    Ok(res)'''
        else:
            cast_expr = _get_value_cast_expr('*i', entry_type, enums)
            return f'''    let mut res = Vec::new();
    if let tlv::TlvItemValue::List(v) = inp {{
        for item in v {{
            if let tlv::TlvItemValue::Int(i) = &item.value {{
                res.push({cast_expr});
            }}
        }}
    }}
    Ok(res)'''
    else:
        # Default fallback
        return '''    let mut res = Vec::new();
    if let tlv::TlvItemValue::List(v) = inp {
        for item in v {
            // TODO: Handle custom struct type decoding
            res.push(Default::default());
        }
    }
    Ok(res)'''


def _generate_single_value_decoder(attr_type: str, nullable: bool, enums: Dict[str, 'MatterEnum'] = None) -> str:
    """Generate decoder logic for a single value (nullable or not).

    Args:
        attr_type: The Matter type of the attribute
        nullable: Whether the value is nullable
        enums: Dictionary of enum definitions

    Returns:
        String containing the decode_logic code block
    """
    tlv_type = MatterType.get_tlv_type(attr_type)
    rust_type = MatterType.get_rust_type(attr_type, enums=enums)

    # Generate the value expression and match pattern for each type
    if tlv_type == "String":
        match_pattern = 'tlv::TlvItemValue::String(v)'
        value_expr = 'v.clone()'
    elif tlv_type == "Bool":
        match_pattern = 'tlv::TlvItemValue::Bool(v)'
        value_expr = '*v'
    elif tlv_type == "OctetString":
        match_pattern = 'tlv::TlvItemValue::OctetString(v)'
        value_expr = 'v.clone()'
    elif tlv_type.startswith("UInt") or tlv_type.startswith("Int"):
        match_pattern = 'tlv::TlvItemValue::Int(v)'
        # Check if this is an enum type
        if attr_type.endswith('Enum') and enums and attr_type in enums:
            enum_name = enums[attr_type].get_rust_enum_name()
            if nullable:
                # For nullable enum, return Result<Option<Enum>>
                return f'''    if let {match_pattern} = inp {{
        Ok({enum_name}::from_u8(*v as u8))
    }} else {{
        Ok(None)
    }}'''
            else:
                # For non-nullable enum, return Result<Enum>
                return f'''    if let {match_pattern} = inp {{
        {enum_name}::from_u8(*v as u8).ok_or_else(|| anyhow::anyhow!("Invalid enum value"))
    }} else {{
        Err(anyhow::anyhow!("Expected Integer"))
    }}'''
        else:
            # Regular integer type
            value_expr = _get_value_cast_expr('*v', attr_type, enums)
    else:
        # Unsupported type
        if nullable:
            return '    // TODO: Handle nullable custom type decoding\n    Ok(None)'
        else:
            return '    // TODO: Handle custom type decoding\n    Err(anyhow::anyhow!("Unsupported type"))'

    # Wrap the value expression based on nullable
    if nullable:
        return f'''    if let {match_pattern} = inp {{
        Ok(Some({value_expr}))
    }} else {{
        Ok(None)
    }}'''
    else:
        return f'''    if let {match_pattern} = inp {{
        Ok({value_expr})
    }} else {{
        Err(anyhow::anyhow!("Expected {tlv_type}"))
    }}'''


def _generate_single_field_encoding(
    field_id: int,
    rust_field: str,
    field_type: str,
    field_entry: Optional[str],
    value_path: str,
    structs: Dict[str, 'MatterStruct'],
    enums: Dict[str, 'MatterEnum'],
    indent: str = "        ",
    fields_vec: str = "fields"
) -> List[str]:
    """Generate encoding lines for a single struct field.

    Args:
        field_id: The TLV field ID
        rust_field: The Rust field name (already converted to snake_case and escaped)
        field_type: The Matter type of the field
        field_entry: For list types, the type of list entries
        value_path: The path to the struct value (e.g., 'v', 'inner', 's')
        structs: Dictionary of struct definitions
        enums: Dictionary of enum definitions
        indent: Indentation string for generated code
        fields_vec: Name of the vector to push to (default: 'fields')

    Returns:
        List of code lines (without trailing newlines)
    """
    lines = []

    if field_type == 'string':
        lines.append(f"{indent}if let Some(x) = {value_path}.{rust_field} {{ {fields_vec}.push(({field_id}, tlv::TlvItemValueEnc::String(x.clone())).into()); }}")
    elif field_type == 'octstr':
        lines.append(f"{indent}if let Some(x) = {value_path}.{rust_field} {{ {fields_vec}.push(({field_id}, tlv::TlvItemValueEnc::OctetString(x.clone())).into()); }}")
    elif field_type == 'bool':
        lines.append(f"{indent}if let Some(x) = {value_path}.{rust_field} {{ {fields_vec}.push(({field_id}, tlv::TlvItemValueEnc::Bool(x)).into()); }}")
    elif is_numeric_or_id_type(field_type) or field_type.endswith('Enum') or field_type.endswith('Bitmap'):
        tlv_type = MatterType.get_tlv_type(field_type)
        cast = _get_value_cast_expr('x', field_type, enums)
        lines.append(f"{indent}if let Some(x) = {value_path}.{rust_field} {{ {fields_vec}.push(({field_id}, tlv::TlvItemValueEnc::{tlv_type}({cast})).into()); }}")
    elif field_type == 'list' and field_entry:
        # Handle list fields
        entry_tlv = MatterType.get_tlv_type(field_entry)
        entry_rust = MatterType.get_rust_type(field_entry, enums=enums)
        if field_entry.endswith('Struct') and structs and field_entry in structs:
            # List of structs - more complex, keep TODO for now
            lines.append(f"{indent}// TODO: list of {field_entry} encoding not fully implemented")
        elif entry_tlv == 'String':
            lines.append(f"{indent}if let Some(listv) = {value_path}.{rust_field} {{ {fields_vec}.push(({field_id}, tlv::TlvItemValueEnc::StructAnon(listv.into_iter().map(|x| (0, tlv::TlvItemValueEnc::String(x.clone())).into()).collect())).into()); }}")
        elif entry_tlv == 'OctetString':
            lines.append(f"{indent}if let Some(listv) = {value_path}.{rust_field} {{ {fields_vec}.push(({field_id}, tlv::TlvItemValueEnc::StructAnon(listv.into_iter().map(|x| (0, tlv::TlvItemValueEnc::OctetString(x.clone())).into()).collect())).into()); }}")
        elif entry_tlv == 'Bool':
            lines.append(f"{indent}if let Some(listv) = {value_path}.{rust_field} {{ {fields_vec}.push(({field_id}, tlv::TlvItemValueEnc::StructAnon(listv.into_iter().map(|x| (0, tlv::TlvItemValueEnc::Bool(x)).into()).collect())).into()); }}")
        elif entry_tlv.startswith('UInt') or entry_tlv.startswith('Int'):
            cast = _get_value_cast_expr('x', field_entry, enums)
            lines.append(f"{indent}if let Some(listv) = {value_path}.{rust_field} {{ {fields_vec}.push(({field_id}, tlv::TlvItemValueEnc::StructAnon(listv.into_iter().map(|x| (0, tlv::TlvItemValueEnc::{entry_tlv}({cast})).into()).collect())).into()); }}")
        else:
            lines.append(f"{indent}// TODO: encoding for list field {rust_field} ({field_entry}) not implemented")
    elif field_type.endswith('Struct') and structs and field_type in structs:
        # Nested struct - generate encoding recursively
        nested = structs[field_type]
        # Use unique variable name to avoid conflicts with parent scope
        nested_vec_name = f'{rust_field}_nested_fields'
        lines.append(f'{indent}if let Some(inner) = {value_path}.{rust_field} {{')
        lines.append(f'{indent}    let mut {nested_vec_name} = Vec::new();')
        for nf_id, nf_name, nf_type, nf_entry in nested.fields:
            nf_rust_field = escape_rust_keyword(convert_to_snake_case(nf_name))
            nested_lines = _generate_single_field_encoding(
                nf_id, nf_rust_field, nf_type, nf_entry, 'inner', structs, enums, indent + "    ", nested_vec_name
            )
            lines.extend(nested_lines)
        lines.append(f'{indent}    {fields_vec}.push(({field_id}, tlv::TlvItemValueEnc::StructInvisible({nested_vec_name})).into());')
        lines.append(f'{indent}}}')
    else:
        lines.append(f"{indent}// TODO: encoding for field {rust_field} ({field_type}) not implemented")

    return lines


def _parse_field_element(field_elem) -> Tuple[int, str, str, Optional[str], bool, bool, Optional[str]]:
    """Parse a field XML element and return all attributes.

    Returns: (field_id, field_name, field_type, field_default, nullable, mandatory, entry_type)
    """
    field_id = int(field_elem.get('id', '0'))
    field_name = field_elem.get('name', 'Unknown')
    field_type = field_elem.get('type', 'uint8')
    field_default = field_elem.get('default')

    # Check for entry type (for list fields)
    entry_elem = field_elem.find('entry')
    entry_type = entry_elem.get('type') if entry_elem is not None else None

    # Check if field is nullable
    quality_elem = field_elem.find('quality')
    nullable = quality_elem.get('nullable', 'false').lower() == 'true' if quality_elem is not None else False

    # Check if field is mandatory
    mandatory_elem = field_elem.find('mandatoryConform')
    mandatory = mandatory_elem is not None

    return field_id, field_name, field_type, field_default, nullable, mandatory, entry_type


class MatterEnum:
    """Represents a Matter enum definition."""

    def __init__(self, name: str):
        self.name = name
        self.items: List[Tuple[int, str, str]] = []  # (value, name, summary)
        self._force_enum_suffix = False  # Set to True to keep "Enum" suffix

    def add_item(self, value: int, item_name: str, summary: str = ""):
        """Add an item to this enum."""
        # Sanitize the item name to be a valid Rust identifier
        sanitized_name = self._sanitize_variant_name(item_name)
        self.items.append((value, sanitized_name, summary))

    def _sanitize_variant_name(self, name: str) -> str:
        """Sanitize enum variant name to be a valid Rust identifier."""
        # Replace spaces with underscores
        name = name.replace(' ', '_')

        # Replace any other invalid characters
        name = re.sub(r'[^a-zA-Z0-9_]', '_', name)

        # Check if it starts with a digit BEFORE capitalizing
        starts_with_digit = name and name[0].isdigit()

        # Ensure it's in PascalCase for enum variants
        # Split by underscore and capitalize each part
        parts = name.split('_')
        name = ''.join(part.capitalize() for part in parts if part)

        # If original started with a digit, prefix with an underscore AFTER PascalCase conversion
        if starts_with_digit:
            name = f"_{name}"

        return name if name else "Unknown"

    def get_rust_enum_name(self) -> str:
        """Convert enum name to PascalCase Rust enum name."""
        # Keep "Enum" suffix if forced (to avoid name collisions)
        if self._force_enum_suffix:
            name = self.name
        else:
            # Remove "Enum" suffix if present for cleaner naming
            name = self.name.replace('Enum', '')
        # Split on capital letters and rejoin in PascalCase
        words = re.findall(r'[A-Z][a-z]*', name)
        return ''.join(words) if words else name

    def generate_rust_enum(self) -> str:
        """Generate Rust enum definition with proper derives."""
        enum_name = self.get_rust_enum_name()

        # Determine the repr type based on the maximum enum value
        max_value = max(value for value, _, _ in self.items) if self.items else 0
        if max_value <= 255:
            repr_type = "u8"
            value_type = "u8"
        elif max_value <= 65535:
            repr_type = "u16"
            value_type = "u16"
        else:
            repr_type = "u32"
            value_type = "u32"

        # Generate enum variants
        variant_definitions = []
        for value, item_name, summary in self.items:
            # Clean up variant name
            variant_name = item_name
            # Add doc comment if summary exists
            if summary:
                variant_definitions.append(f"    /// {summary}")
            variant_definitions.append(f"    {variant_name} = {value},")

        variants_str = "\n".join(variant_definitions)

        # Generate the enum with proper derives
        # For u8 enums, don't add the wrapper from_u8 method
        if value_type == "u8":
            return f'''#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr({repr_type})]
pub enum {enum_name} {{
{variants_str}
}}

impl {enum_name} {{
    /// Convert from u8 value
    pub fn from_u8(value: u8) -> Option<Self> {{
        match value {{
{self._generate_from_value_arms(value_type)}
            _ => None,
        }}
    }}

    /// Convert to u8 value
    pub fn to_u8(self) -> u8 {{
        self as u8
    }}
}}

impl From<{enum_name}> for u8 {{
    fn from(val: {enum_name}) -> Self {{
        val as u8
    }}
}}'''
        else:
            return f'''#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr({repr_type})]
pub enum {enum_name} {{
{variants_str}
}}

impl {enum_name} {{
    /// Convert from u8 value (promoted to {value_type})
    pub fn from_u8(value: u8) -> Option<Self> {{
        Self::from_{value_type}(value as {value_type})
    }}

    /// Convert from {value_type} value
    pub fn from_{value_type}(value: {value_type}) -> Option<Self> {{
        match value {{
{self._generate_from_value_arms(value_type)}
            _ => None,
        }}
    }}

    /// Convert to u8 value (truncated if value > 255)
    pub fn to_u8(self) -> u8 {{
        self as u8
    }}

    /// Convert to {value_type} value
    pub fn to_{value_type}(self) -> {value_type} {{
        self as {value_type}
    }}
}}

impl From<{enum_name}> for {value_type} {{
    fn from(val: {enum_name}) -> Self {{
        val as {value_type}
    }}
}}'''

    def _generate_from_value_arms(self, value_type: str) -> str:
        """Generate match arms for from_value conversion."""
        enum_name = self.get_rust_enum_name()
        arms = []
        for value, item_name, _ in self.items:
            arms.append(f"            {value} => Some({enum_name}::{item_name}),")
        return "\n".join(arms)


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
    
    def generate_rust_struct(self, structs: Dict[str, 'MatterStruct'] = None, enums: Dict[str, MatterEnum] = None) -> str:
        """Generate Rust struct definition."""
        struct_name = self.get_rust_struct_name()

        field_definitions = []
        for field_id, field_name, field_type, entry_type in self.fields:
            rust_field_name = convert_to_snake_case(field_name)
            rust_field_name = escape_rust_keyword(rust_field_name)  # Escape Rust keywords

            if field_type == 'list' and entry_type:
                # Handle list fields with specific entry types
                if entry_type.endswith('Struct'):
                    # Skip if struct not defined in this cluster (cross-cluster reference)
                    if structs and entry_type not in structs:
                        continue
                    # Custom struct type - convert to PascalCase
                    entry_rust_type = entry_type.replace('Struct', '')
                    entry_rust_type = ''.join(word.capitalize() for word in re.findall(r'[A-Z][a-z]*', entry_rust_type))
                    rust_type = f"Vec<{entry_rust_type}>"
                else:
                    # Primitive type or known type
                    entry_rust_type = MatterType.get_rust_type(entry_type, enums=enums)
                    rust_type = f"Vec<{entry_rust_type}>"
            elif field_type.endswith('Struct'):
                # Skip if struct not defined in this cluster (cross-cluster reference)
                if structs and field_type not in structs:
                    continue
                # Handle custom struct type
                if structs and field_type in structs:
                    # Use the struct's rust name
                    rust_type = structs[field_type].get_rust_struct_name()
                else:
                    # Fallback: convert struct name
                    rust_type = field_type.replace('Struct', '')
                    rust_type = ''.join(word.capitalize() for word in re.findall(r'[A-Z][a-z]*', rust_type))
            else:
                rust_type = MatterType.get_rust_type(field_type, enums=enums)

            # Make all struct fields optional since they might not be present in TLV
            field_definitions.append(f"    pub {rust_field_name}: Option<{rust_type}>,")

        fields_str = "\n".join(field_definitions)

        return f'''#[derive(Debug, serde::Serialize)]
pub struct {struct_name} {{
{fields_str}
}}'''
    
    def generate_decode_function(self, is_list: bool = False, enums: Dict[str, 'MatterEnum'] = None) -> str:
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
                    rust_type = MatterType.get_rust_type(entry_type, enums=enums)
                    cast_expr = _get_value_cast_expr('*v', entry_type, enums)
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
                rust_type = MatterType.get_rust_type(field_type, enums=enums)
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
        'epoch-us': 'UInt64',
        'elapsed-s': 'UInt32',
        'power-mW': 'UInt32',
        'energy-mWh': 'UInt64',
        'temperature': 'Int16',
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
    def get_rust_type(cls, matter_type: str, is_list: bool = False, enums: Dict[str, 'MatterEnum'] = None) -> str:
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
            'epoch-us': 'u64',
            'elapsed-s': 'u32',
            'power-mW': 'u32',
            'energy-mWh': 'u64',
            'temperature': 'i16',
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

        # Check if this is an enum type and we have the enum definition
        if matter_type.endswith('Enum') and enums and matter_type in enums:
            enum_obj = enums[matter_type]
            base_type = enum_obj.get_rust_enum_name()
        elif matter_type.endswith('Enum'):
            # Enum without definition - fall back to u8
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
    
    def get_rust_return_type(self, structs: Dict[str, MatterStruct] = None, enums: Dict[str, 'MatterEnum'] = None) -> str:
        """Get the Rust return type for this attribute."""
        if self.is_list:
            if self.entry_type:
                # Check if it's a custom struct
                if structs and self.entry_type in structs:
                    struct_name = structs[self.entry_type].get_rust_struct_name()
                    return f"Vec<{struct_name}>"
                else:
                    # Map entry types to Rust types
                    entry_rust_type = MatterType.get_rust_type(self.entry_type, enums=enums)
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
                rust_type = MatterType.get_rust_type(self.attr_type, enums=enums)
                if self.nullable:
                    return f"Option<{rust_type}>"
                return rust_type
    
    def generate_decode_function(self, structs: Dict[str, MatterStruct] = None, enums: Dict[str, 'MatterEnum'] = None) -> str:
        """Generate Rust decode function for this attribute."""
        func_name = self.get_rust_function_name()
        return_type = self.get_rust_return_type(structs, enums)
        clean_id = self.id
        
        if self.is_list:
            if self.entry_type and structs and self.entry_type in structs:
                # Use custom struct decoder
                struct = structs[self.entry_type]
                struct_name = struct.get_rust_struct_name()

                # Generate field assignments
                field_assignments = _generate_struct_field_assignments(struct.fields, structs, enums, "item")
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
                decode_logic = _generate_list_decoder(self.entry_type, enums)
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
                field_assignments = _generate_struct_field_assignments(struct.fields, structs, enums, "item")
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
                # For non-struct types, use unified decoder
                decode_logic = _generate_single_value_decoder(self.attr_type, self.nullable, enums)
        
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
    
    def get_tlv_encoding(self, param_name: str, structs: Dict[str, 'MatterStruct'], enums: Dict[str, 'MatterEnum'] = None) -> str:
        """Generate TLV encoding line for this field.

        `structs` provides parsed struct definitions so that when this field is a
        list of Structs we can generate code that walks the Rust struct fields
        and emits TLV entries for present Option<> fields.
        """
        if self.is_list:
            if self.entry_type:
                # If the entry is a struct and we have its definition, generate
                # code that accepts `Vec<Struct>` and encodes each struct's
                # present fields into a TLV anonymous struct element.
                if self.entry_type.endswith('Struct') and structs and self.entry_type in structs:
                    target = structs[self.entry_type]
                    struct_rust_name = target.get_rust_struct_name()
                    # Build per-field push statements for the inner struct
                    inner_lines = []
                    for f_id, f_name, f_type, f_entry in target.fields:
                        rust_field = escape_rust_keyword(convert_to_snake_case(f_name))
                        # Handle list fields inside struct
                        if f_type == 'list' and f_entry:
                            # List of structs
                            if f_entry.endswith('Struct') and structs and f_entry in structs:
                                nested = structs[f_entry]
                                nested_lines = []
                                for nf_id, nf_name, nf_type, nf_entry in nested.fields:
                                    nf_rust_field = escape_rust_keyword(convert_to_snake_case(nf_name))
                                    field_lines = _generate_single_field_encoding(
                                        nf_id, nf_rust_field, nf_type, nf_entry, 'inner', structs, enums,
                                        "                                ", 'nested_fields'
                                    )
                                    nested_lines.extend(field_lines)

                                inner_lines.append(f"                    if let Some(listv) = v.{rust_field} {{")
                                inner_lines.append("                        let inner_vec: Vec<_> = listv.into_iter().map(|inner| {")
                                inner_lines.append("                            let mut nested_fields = Vec::new();")
                                inner_lines += nested_lines
                                inner_lines.append(f"                            (0, tlv::TlvItemValueEnc::StructInvisible(nested_fields)).into()")
                                inner_lines.append("                        }).collect();")
                                inner_lines.append(f"                        fields.push(({f_id}, tlv::TlvItemValueEnc::StructAnon(inner_vec)).into());")
                                inner_lines.append("                    }")
                            else:
                                # Primitive list inside struct
                                entry_tlv = MatterType.get_tlv_type(f_entry)
                                entry_rust = MatterType.get_rust_type(f_entry, enums=enums)
                                if entry_tlv == 'String':
                                    inner_lines.append(f"                    if let Some(listv) = v.{rust_field} {{ fields.push(({f_id}, tlv::TlvItemValueEnc::StructAnon(listv.into_iter().map(|x| (0, tlv::TlvItemValueEnc::String(x.clone())).into()).collect())).into()); }}")
                                elif entry_tlv == 'OctetString':
                                    inner_lines.append(f"                    if let Some(listv) = v.{rust_field} {{ fields.push(({f_id}, tlv::TlvItemValueEnc::StructAnon(listv.into_iter().map(|x| (0, tlv::TlvItemValueEnc::OctetString(x.clone())).into()).collect())).into()); }}")
                                elif entry_tlv == 'Bool':
                                    inner_lines.append(f"                    if let Some(listv) = v.{rust_field} {{ fields.push(({f_id}, tlv::TlvItemValueEnc::StructAnon(listv.into_iter().map(|x| (0, tlv::TlvItemValueEnc::Bool(x)).into()).collect())).into()); }}")
                                elif entry_tlv.startswith('UInt') or entry_tlv.startswith('Int'):
                                    cast = _get_value_cast_expr('x', f_entry, enums)
                                    inner_lines.append(f"                    if let Some(listv) = v.{rust_field} {{ fields.push(({f_id}, tlv::TlvItemValueEnc::StructAnon(listv.into_iter().map(|x| (0, tlv::TlvItemValueEnc::{entry_tlv}({cast})).into()).collect())).into()); }}")
                                else:
                                    inner_lines.append(f"                    // TODO: encoding for list field {f_name} ({f_entry}) not implemented")
                        # Primitive and simple types
                        elif f_type in ('string', 'octstr', 'bool') or f_type.endswith('Enum') or f_type.endswith('Bitmap') or is_numeric_or_id_type(f_type):
                            field_lines = _generate_single_field_encoding(
                                f_id, rust_field, f_type, f_entry, 'v', structs, enums, "                    "
                            )
                            inner_lines.extend(field_lines)
                        elif f_type.endswith('Struct') and structs and f_type in structs:
                            # Nested struct: encode nested fields into a nested invisible struct
                            nested = structs[f_type]
                            nested_lines = []
                            for nf_id, nf_name, nf_type, nf_entry in nested.fields:
                                nf_rust_field = escape_rust_keyword(convert_to_snake_case(nf_name))
                                field_lines = _generate_single_field_encoding(
                                    nf_id, nf_rust_field, nf_type, nf_entry, 'inner', structs, enums,
                                    "                            ", 'nested_fields'
                                )
                                nested_lines.extend(field_lines)

                            inner_lines.append('                    if let Some(inner) = v.%s {'.replace('%s', rust_field))
                            inner_lines.append('                        let mut nested_fields = Vec::new();')
                            inner_lines += nested_lines
                            inner_lines.append('                        fields.push(({id}, tlv::TlvItemValueEnc::StructInvisible(nested_fields)).into());'.replace('{id}', str(f_id)))
                            inner_lines.append('                    }')
                        else:
                            inner_lines.append(f"                    // TODO: encoding for field {f_name} ({f_type}) not implemented")

                    inner_body = "\n".join(inner_lines)
                    # Generate the final map/collect expression with correct closure
                    # Note: the opening brace after |v| opens the closure body
                    closure_start = f"        ({self.id}, tlv::TlvItemValueEnc::StructAnon({param_name}.into_iter().map(|v| " + "{\n"
                    closure_end = "                }).collect())).into(),"
                    return closure_start + "                    let mut fields = Vec::new();\n" + inner_body + "\n                    (0, tlv::TlvItemValueEnc::StructInvisible(fields)).into()\n" + closure_end

                # Primitive entry types: map Matter TLV type to the correct
                # TlvItemValueEnc variant and cast elements to the appropriate
                # Rust type when needed.
                entry_tlv = MatterType.get_tlv_type(self.entry_type)
                entry_rust = MatterType.get_rust_type(self.entry_type, enums=enums)

                if entry_tlv == 'String':
                    return f"        ({self.id}, tlv::TlvItemValueEnc::StructAnon({param_name}.into_iter().map(|v| (0, tlv::TlvItemValueEnc::String(v)).into()).collect())).into(),"
                if entry_tlv == 'OctetString':
                    return f"        ({self.id}, tlv::TlvItemValueEnc::StructAnon({param_name}.into_iter().map(|v| (0, tlv::TlvItemValueEnc::OctetString(v)).into()).collect())).into(),"
                if entry_tlv == 'Bool':
                    return f"        ({self.id}, tlv::TlvItemValueEnc::StructAnon({param_name}.into_iter().map(|v| (0, tlv::TlvItemValueEnc::Bool(v)).into()).collect())).into(),"
                if entry_tlv.startswith('UInt') or entry_tlv.startswith('Int'):
                    # Cast numeric items to the target Rust type when necessary
                    cast = _get_value_cast_expr('v', self.entry_type, enums)
                    return f"        ({self.id}, tlv::TlvItemValueEnc::StructAnon({param_name}.into_iter().map(|v| (0, tlv::TlvItemValueEnc::{entry_tlv}({cast})).into()).collect())).into(),"

                # Fallback: preserve previous behavior but use the element as-is
                return f"        ({self.id}, tlv::TlvItemValueEnc::StructAnon({param_name}.into_iter().map(|v| (0, tlv::TlvItemValueEnc::UInt8(v)).into()).collect())).into(),"
            else:
                # No entry type specified — keep previous default (UInt8)
                return f"        ({self.id}, tlv::TlvItemValueEnc::StructAnon({param_name}.into_iter().map(|v| (0, tlv::TlvItemValueEnc::UInt8(v)).into()).collect())).into(),"
        
        tlv_type = MatterType.get_tlv_type(self.field_type)
        
        if self.nullable:
            # Handle nullable fields
            if self.field_type.endswith('Struct') and structs and self.field_type in structs:
                # Handle nullable struct fields - encode if Some, otherwise use empty struct
                struct_def = structs[self.field_type]
                lines = []
                lines.append(f"        // Encode optional struct {self.field_type}")
                lines.append(f"        let {param_name}_enc = if let Some(s) = {param_name} {{")
                lines.append(f"            let mut fields = Vec::new();")
                
                for f_id, f_name, f_type, f_entry in struct_def.fields:
                    rust_field = escape_rust_keyword(convert_to_snake_case(f_name))
                    field_lines = _generate_single_field_encoding(
                        f_id, rust_field, f_type, f_entry, 's', structs, enums, "            "
                    )
                    lines.extend(field_lines)
                
                lines.append(f"            tlv::TlvItemValueEnc::StructInvisible(fields)")
                lines.append(f"        }} else {{")
                lines.append(f"            tlv::TlvItemValueEnc::StructInvisible(Vec::new())")
                lines.append(f"        }};")
                lines.append(f"        ({self.id}, {param_name}_enc).into(),")
                return "\n".join(lines)
            elif self.field_type.endswith('Struct'):
                # Struct type not defined in this cluster - skip
                return ""
            
            # For Enum types, use proper conversion
            if self.field_type.endswith('Enum'):
                # Check if we have the enum definition
                if enums and self.field_type in enums:
                    enum_name = enums[self.field_type].get_rust_enum_name()
                    if self.default and self.default.lower() in ['null', 'none']:
                        # Use Default implementation for enum (should be first variant typically)
                        param_expr = f"{param_name}.map(|e| e.to_u8()).unwrap_or_default()"
                    else:
                        default_value = self._get_default_value()
                        param_expr = f"{param_name}.map(|e| e.to_u8()).unwrap_or({default_value})"
                else:
                    # Fallback to u8 if enum not defined
                    if self.default and self.default.lower() in ['null', 'none']:
                        param_expr = f"{param_name}.unwrap_or_default()"
                    else:
                        default_value = self._get_default_value()
                        param_expr = f"{param_name}.unwrap_or({default_value})"
            else:
                if self.default and self.default.lower() in ['null', 'none']:
                    param_expr = f"{param_name}.unwrap_or_default()"
                else:
                    default_value = self._get_default_value()
                    param_expr = f"{param_name}.unwrap_or({default_value})"
            
            return f"        ({self.id}, tlv::TlvItemValueEnc::{tlv_type}({param_expr})).into(),"
        else:
            # For non-nullable Enum types, use proper conversion
            if self.field_type.endswith('Enum'):
                # Check if we have the enum definition
                if enums and self.field_type in enums:
                    param_expr = f"{param_name}.to_u8()"
                else:
                    # Fallback: assume it's already u8
                    param_expr = param_name
                return f"        ({self.id}, tlv::TlvItemValueEnc::{tlv_type}({param_expr})).into(),"
            elif self.field_type.endswith('Struct') and structs and self.field_type in structs:
                # Single struct parameter - need to encode its fields
                struct_def = structs[self.field_type]
                lines = []
                lines.append(f"        // Encode struct {self.field_type}")
                lines.append(f"        let mut {param_name}_fields = Vec::new();")
                
                # Track if any field is actually encoded (not TODO)
                has_encodable_fields = False

                for f_id, f_name, f_type, f_entry in struct_def.fields:
                    rust_field = escape_rust_keyword(convert_to_snake_case(f_name))
                    field_lines = _generate_single_field_encoding(
                        f_id, rust_field, f_type, f_entry, param_name, structs, enums,
                        "        ", f"{param_name}_fields"
                    )
                    # Check if this field is actually encodable (not a TODO comment)
                    if field_lines and not any('TODO' in line for line in field_lines):
                        has_encodable_fields = True
                    lines.extend(field_lines)
                
                # If no fields are encodable, suppress warnings and remove mut
                if not has_encodable_fields:
                    lines.insert(0, f"        let _ = {param_name}; // Suppress unused warning - struct has no encodable fields")
                    lines[2] = f"        let {param_name}_fields: Vec<tlv::TlvItemEnc> = Vec::new();  // Empty struct"
                
                lines.append(f"        ({self.id}, tlv::TlvItemValueEnc::StructInvisible({param_name}_fields)).into(),")
                return "\n".join(lines)
            else:
                param_expr = param_name
                return f"        ({self.id}, tlv::TlvItemValueEnc::{tlv_type}({param_expr})).into(),"
    
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
    
    def generate_rust_function(self, structs: Dict[str, MatterStruct], enums: Dict[str, 'MatterEnum'] = None) -> str:
        """Generate complete Rust function for encoding this command."""
        func_name = self.get_rust_function_name()

        # Generate function parameters
        params = []
        for field in self.fields:
            param_name = field.get_rust_param_name()
            # If this is a list of a custom struct, expose Vec<StructName>
            if field.is_list and field.entry_type and structs and field.entry_type in structs:
                item_struct = structs[field.entry_type]
                rust_type = f"Vec<{item_struct.get_rust_struct_name()}>"
            elif not field.is_list and field.field_type.endswith('Struct') and structs and field.field_type in structs:
                # Single struct field
                struct_def = structs[field.field_type]
                rust_type = struct_def.get_rust_struct_name()
            elif not field.is_list and field.field_type.endswith('Struct') and (not structs or field.field_type not in structs):
                # Skip fields that reference undefined structs from other clusters
                continue
            elif not field.is_list and field.field_type.endswith('Enum'):
                # Check if we have the enum definition
                if enums and field.field_type in enums:
                    rust_type = enums[field.field_type].get_rust_enum_name()
                else:
                    # Fallback to u8 if enum not defined
                    rust_type = 'u8'
            else:
                # Use MatterType mapping (handles primitive lists when is_list=True)
                rust_type = MatterType.get_rust_type(field.entry_type if field.is_list and field.entry_type else field.field_type, field.is_list, enums=enums)

            if field.nullable:
                rust_type = f"Option<{rust_type}>"

            params.append(f"{param_name}: {rust_type}")

        param_str = ", ".join(params) if params else ""

        # Generate TLV encoding - collect both pre-statements and field encodings
        pre_statements = []  # Statements that need to go before vec![]
        tlv_fields = []  # Field encodings that go inside vec![]

        for field in self.fields:
            param_name = field.get_rust_param_name()
            encoding_result = field.get_tlv_encoding(param_name, structs, enums)
            
            # Check if this is a multi-line struct encoding that needs pre-statements
            if '\n' in encoding_result and field.field_type.endswith('Struct'):
                # Split into pre-statements and the final field line
                lines = encoding_result.split('\n')
                # First line is comment, middle lines are statements, last line is the field push
                pre_statements.extend(lines[:-1])  # Everything except last line
                tlv_fields.append(lines[-1])  # Last line
            else:
                tlv_fields.append(encoding_result)
        
        # Generate pre-statement block (if any)
        pre_stmt_str = "\n    ".join(pre_statements) if pre_statements else ""
        tlv_fields_str = "\n".join(tlv_fields) if tlv_fields else "        // No fields"
        
        # Clean up command ID format
        clean_id = self.id
        
        # Generate function
        if pre_statements:
            function = f'''/// Encode {self.name} command ({clean_id})
pub fn {func_name}({param_str}) -> anyhow::Result<Vec<u8>> {{
    {pre_stmt_str}
    let tlv = tlv::TlvItemEnc {{
        tag: 0,
        value: tlv::TlvItemValueEnc::StructInvisible(vec![
{tlv_fields_str}
        ]),
    }};
    Ok(tlv.encode()?)
}}'''
        else:
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
                field_id, field_name, field_type, field_default, nullable, mandatory, entry_type = _parse_field_element(field_elem)
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
                            field_id, field_name, field_type, field_default, nullable, mandatory, entry_type = _parse_field_element(field_elem)
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

    def parse_enums(self) -> Dict[str, MatterEnum]:
        """Parse all enum definitions from the XML."""
        enums = {}

        data_types_elem = self.root.find('dataTypes')
        if data_types_elem is None:
            return enums

        for enum_elem in data_types_elem.findall('enum'):
            enum_name = enum_elem.get('name', 'Unknown')
            enum = MatterEnum(enum_name)

            # Parse enum items
            for item_elem in enum_elem.findall('item'):
                value_str = item_elem.get('value', '0')
                item_name = item_elem.get('name', 'Unknown')
                summary = item_elem.get('summary', '')

                # Parse the value (can be decimal or hex)
                try:
                    if value_str.startswith('0x') or value_str.startswith('0X'):
                        value = int(value_str, 16)
                    else:
                        value = int(value_str)
                except ValueError:
                    value = 0

                enum.add_item(value, item_name, summary)

            enums[enum_name] = enum

        return enums


def generate_json_dispatcher_function(cluster_id: str, attributes: List[AttributeField], structs: Dict[str, MatterStruct]) -> str:
    """Generate a JSON dispatcher function that routes attribute decoding based on attribute ID."""
    if not attributes:
        return ""
    
    clean_cluster_id = cluster_id
    
    # Generate match arms for each unique attribute (deduplicate by ID)
    match_arms = []
    seen_ids = set()
    for attribute in attributes:
        clean_attr_id = attribute.id

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

    # Generate attribute list entries
    attribute_entries = []
    seen_ids = set()
    
    for attribute in attributes:
        clean_attr_id = attribute.id
        
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
    enums = parser.parse_enums()

    # Detect name collisions between enums and structs
    # If an enum has the same name as a struct, rename the enum by NOT removing the "Enum" suffix
    enum_names = {enum.get_rust_enum_name() for enum in enums.values()}
    struct_names = {struct.get_rust_struct_name() for struct in structs.values()}

    # Find collisions and keep track of which enums to preserve "Enum" suffix
    collisions = enum_names & struct_names

    # Create a new enums dict with adjusted names
    if collisions:
        adjusted_enums = {}
        for enum_key, enum_obj in enums.items():
            if enum_obj.get_rust_enum_name() in collisions:
                # Keep the original name with "Enum" suffix
                enum_obj._force_enum_suffix = True
            adjusted_enums[enum_key] = enum_obj
        enums = adjusted_enums

    # Handle duplicate enum variants (like "Reservedforfutureuse" appearing twice)
    for enum_obj in enums.values():
        seen_names = set()
        unique_items = []
        for value, name, summary in enum_obj.items:
            if name in seen_names:
                # Append the value to make it unique
                unique_name = f"{name}{value}"
                unique_items.append((value, unique_name, summary))
            else:
                seen_names.add(name)
                unique_items.append((value, name, summary))
        enum_obj.items = unique_items

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
    if commands_with_fields or attributes or structs or enums:
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

    # Generate enum definitions (before structs as structs may use enums)
    if enums:
        code += "// Enum definitions\n\n"
        for enum in enums.values():
            code += enum.generate_rust_enum() + "\n\n"

    # Generate struct definitions
    if structs:
        code += "// Struct definitions\n\n"
        for struct in structs.values():
            code += struct.generate_rust_struct(structs, enums) + "\n\n"

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
                code += command.generate_rust_function(structs, enums) + "\n\n"
                generated_functions.add(func_name)

    # Generate attribute decoders
    if attributes:
        code += "// Attribute decoders\n\n"
        generated_functions = set()
        for attribute in attributes:
            func_name = attribute.get_rust_function_name()
            if func_name not in generated_functions:
                code += attribute.generate_decode_function(structs, enums) + "\n\n"
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
