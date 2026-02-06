"""
Helper functions for TLV encoding and decoding code generation.
"""

import re
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

from ..naming import convert_to_snake_case, escape_rust_keyword, is_numeric_or_id_type
from ..type_mapping import MatterType

if TYPE_CHECKING:
    from .enums import MatterEnum, MatterBitmap
    from .structs import MatterStruct
    from .field import MatterField




def _get_value_cast_expr(value_var: str, matter_type: str, enums: Optional[Dict[str, 'MatterEnum']] = None, bitmaps: Optional[Dict[str, 'MatterBitmap']] = None) -> str:
    """Generate appropriate cast expression for a value based on its Matter type.

    Args:
        value_var: The variable name to cast (e.g., 'v', 'x', '*i')
        matter_type: The Matter type string
        enums: Dictionary of enum definitions
        bitmaps: Dictionary of bitmap definitions

    Returns:
        A string expression for casting the value
    """
    if matter_type.endswith('Enum') and enums and matter_type in enums:
        return f'{value_var}.to_u8()'
    if matter_type.endswith('Bitmap') and bitmaps and matter_type in bitmaps:
        return value_var
    rust_type = MatterType.get_rust_type(matter_type, enums=enums, bitmaps=bitmaps)

    # Decoding context: variable comes from TlvItemValue::Int which is always u64
    # We need to cast unless the target type is also u64
    if value_var.startswith('*'):
        # Dereferenced variable from pattern match - this is a decoding path
        return value_var if rust_type == 'u64' else f'{value_var} as {rust_type}'

    # Encoding context: variable already has the correct rust_type
    # Get the TLV type and its native Rust type to avoid unnecessary casts
    tlv_type = MatterType.get_tlv_type(matter_type, bitmaps=bitmaps)
    tlv_rust = MatterType.TLV_TO_RUST.get(tlv_type)

    # Only cast if types differ (this should rarely happen in encoding)
    if rust_type == tlv_rust:
        return value_var
    else:
        return f'{value_var} as {rust_type}'


def _generate_list_item_filter_expr(entry_type: str, enums: Optional[Dict[str, 'MatterEnum']] = None, bitmaps: Optional[Dict[str, 'MatterBitmap']] = None) -> str:
    """Generate the filter_map expression for decoding a list item.

    Returns a string like: 'if let tlv::TlvItemValue::String(s) = &e.value { Some(s.clone()) } else { None }'
    """
    tlv_type = MatterType.get_tlv_type(entry_type, bitmaps=bitmaps)
    rust_type = MatterType.get_rust_type(entry_type, enums=enums, bitmaps=bitmaps)

    if tlv_type == "String":
        return 'if let tlv::TlvItemValue::String(v) = &e.value { Some(v.clone()) } else { None }'
    elif tlv_type == "Bool":
        return 'if let tlv::TlvItemValue::Bool(v) = &e.value { Some(*v) } else { None }'
    elif tlv_type == "OctetString":
        return 'if let tlv::TlvItemValue::OctetString(v) = &e.value { Some(v.clone()) } else { None }'
    elif tlv_type.startswith("UInt") or tlv_type.startswith("Int"):
        if entry_type.endswith('Enum') and enums and entry_type in enums:
            return f'if let tlv::TlvItemValue::Int(v) = &e.value {{ {rust_type}::from_u8(*v as u8) }} else {{ None }}'
        elif entry_type.endswith('Bitmap') and bitmaps and entry_type in bitmaps:
            bitmap_obj = bitmaps[entry_type]
            base_type = bitmap_obj.get_base_type()
            return f'if let tlv::TlvItemValue::Int(v) = &e.value {{ Some(*v as {base_type}) }} else {{ None }}'
        else:
            cast_expr = _get_value_cast_expr('*v', entry_type, enums, bitmaps)
            return f'if let tlv::TlvItemValue::Int(v) = &e.value {{ Some({cast_expr}) }} else {{ None }}'
    else:
        return 'None  // Unsupported type'


def _generate_list_decoder(entry_type: str, enums: Optional[Dict[str, 'MatterEnum']] = None, bitmaps: Optional[Dict[str, 'MatterBitmap']] = None) -> str:
    """Generate complete list decoder code for a given entry type.

    Args:
        entry_type: The type of items in the list
        enums: Dictionary of enum definitions
        bitmaps: Dictionary of bitmap definitions

    Returns:
        String containing the complete decode_logic code block
    """
    tlv_type = MatterType.get_tlv_type(entry_type, bitmaps=bitmaps)
    rust_type = MatterType.get_rust_type(entry_type, enums=enums, bitmaps=bitmaps)

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
        elif entry_type.endswith('Bitmap') and bitmaps and entry_type in bitmaps:
            bitmap_obj = bitmaps[entry_type]
            base_type = bitmap_obj.get_base_type()
            return f'''    let mut res = Vec::new();
    if let tlv::TlvItemValue::List(v) = inp {{
        for item in v {{
            if let tlv::TlvItemValue::Int(i) = &item.value {{
                res.push(*i as {base_type});
            }}
        }}
    }}
    Ok(res)'''
        else:
            cast_expr = _get_value_cast_expr('*i', entry_type, enums, bitmaps)
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


def _generate_single_value_decoder(attr_type: str, nullable: bool, enums: Optional[Dict[str, 'MatterEnum']] = None, bitmaps: Optional[Dict[str, 'MatterBitmap']] = None) -> str:
    """Generate decoder logic for a single value (nullable or not).

    Args:
        attr_type: The Matter type of the attribute
        nullable: Whether the value is nullable
        enums: Dictionary of enum definitions
        bitmaps: Dictionary of bitmap definitions

    Returns:
        String containing the decode_logic code block
    """
    tlv_type = MatterType.get_tlv_type(attr_type, bitmaps=bitmaps)
    rust_type = MatterType.get_rust_type(attr_type, enums=enums, bitmaps=bitmaps)

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
        # Check if this is a bitmap type
        elif attr_type.endswith('Bitmap') and bitmaps and attr_type in bitmaps:
            bitmap_obj = bitmaps[attr_type]
            bitmap_name = bitmap_obj.get_rust_bitmap_name()
            base_type = bitmap_obj.get_base_type()
            if nullable:
                # For nullable bitmap, return Result<Option<Bitmap>>
                return f'''    if let {match_pattern} = inp {{
        Ok(Some(*v as {base_type}))
    }} else {{
        Ok(None)
    }}'''
            else:
                # For non-nullable bitmap, return Result<Bitmap>
                return f'''    if let {match_pattern} = inp {{
        Ok(*v as {base_type})
    }} else {{
        Err(anyhow::anyhow!("Expected Integer"))
    }}'''
        else:
            # Regular integer type
            value_expr = _get_value_cast_expr('*v', attr_type, enums, bitmaps)
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


def _generate_rust_struct_definition(struct_name: str, struct_fields: List[Tuple[int, str, str, Optional[str]]], structs: Optional[Dict[str, 'MatterStruct']] = None, enums: Optional[Dict[str, 'MatterEnum']] = None, bitmaps: Optional[Dict[str, 'MatterBitmap']] = None) -> str:
    """Generate a Rust struct definition with optional fields.

    This is shared between MatterStruct and MatterCommandResponse to avoid duplication.

    Args:
        struct_name: The name of the struct (already in PascalCase)
        struct_fields: List of (id, name, type, entry_type) tuples
        structs: Dictionary of struct definitions
        enums: Dictionary of enum definitions
        bitmaps: Dictionary of bitmap definitions

    Returns:
        String containing the complete struct definition
    """
    field_definitions = []
    for field_id, field_name, field_type, entry_type in struct_fields:
        rust_field_name = convert_to_snake_case(field_name)
        rust_field_name = escape_rust_keyword(rust_field_name)

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
                entry_rust_type = MatterType.get_rust_type(entry_type, enums=enums, bitmaps=bitmaps)
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
            rust_type = MatterType.get_rust_type(field_type, enums=enums, bitmaps=bitmaps)

        # Make all struct fields optional since they might not be present in TLV
        # Add custom serialization for octstr fields (to serialize as hex string)
        if field_type == 'octstr':
            field_definitions.append(f"    #[serde(serialize_with = \"serialize_opt_bytes_as_hex\")]")
            field_definitions.append(f"    pub {rust_field_name}: Option<{rust_type}>,")
        elif field_type == 'list' and entry_type == 'octstr':
            # Handle list of octstr
            field_definitions.append(f"    #[serde(serialize_with = \"serialize_opt_vec_bytes_as_hex\")]")
            field_definitions.append(f"    pub {rust_field_name}: Option<{rust_type}>,")
        else:
            field_definitions.append(f"    pub {rust_field_name}: Option<{rust_type}>,")

    fields_str = "\n".join(field_definitions)

    return f'''#[derive(Debug, serde::Serialize)]
pub struct {struct_name} {{
{fields_str}
}}'''


def _generate_struct_field_assignments(struct_fields: List[Tuple[int, str, str, Optional[str]]], structs: Dict[str, 'MatterStruct'], enums: Dict[str, 'MatterEnum'], item_var: str, bitmaps: Optional[Dict[str, 'MatterBitmap']] = None) -> List[str]:
    """Generate Rust field assignments for a struct from a TLV item.

    Fields with undefined cross-cluster struct types are skipped to match
    the struct definition generation logic.
    """
    field_assignments = []
    for field_id, field_name, field_type, entry_type in struct_fields:
        rust_field_name = convert_to_snake_case(field_name)
        rust_field_name = escape_rust_keyword(rust_field_name)

        # Skip fields with undefined cross-cluster struct types (consistent with struct generation)
        if field_type.endswith('Struct') and structs and field_type not in structs:
            continue  # Cross-cluster struct reference, skip
        if field_type == 'list' and entry_type and entry_type.endswith('Struct') and structs and entry_type not in structs:
            continue  # List of cross-cluster struct references, skip

        if field_type == 'list' and entry_type:
            if entry_type.endswith('Struct') and structs and entry_type in structs:
                target_struct = structs[entry_type]
                struct_rust_name = target_struct.get_rust_struct_name()
                nested_assignments_str = "\n".join(_generate_struct_field_assignments(target_struct.fields, structs, enums, "list_item", bitmaps))
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
                rust_type = MatterType.get_rust_type(entry_type, enums=enums, bitmaps=bitmaps)
                value_map = _generate_list_item_filter_expr(entry_type, enums=enums, bitmaps=bitmaps)

                field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(tlv::TlvItemValue::List(l)) = {item_var}.get(&[{field_id}]) {{
                        let items: Vec<{rust_type}> = l.iter().filter_map(|e| {{ {value_map} }}).collect();
                        Some(items)
                    }} else {{
                        None
                    }}
                }},''')
        elif is_numeric_or_id_type(field_type):
            from ..naming import build_numeric_field_assignment
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
        elif field_type.endswith('Bitmap'):
            # Check if we have the bitmap definition
            if bitmaps and field_type in bitmaps:
                bitmap_obj = bitmaps[field_type]
                bitmap_name = bitmap_obj.get_rust_bitmap_name()
                base_type = bitmap_obj.get_base_type()
                field_assignments.append(f"                {rust_field_name}: {item_var}.get_int(&[{field_id}]).map(|v| v as {base_type}),")
            else:
                # Fallback to u8 if bitmap not defined
                field_assignments.append(f"                {rust_field_name}: {item_var}.get_int(&[{field_id}]).map(|v| v as u8),")
        elif field_type.endswith('Struct') and structs and field_type in structs:
            # In-cluster struct - generate nested struct decoding
            target_struct = structs[field_type]
            struct_rust_name = target_struct.get_rust_struct_name()
            nested_assignments_str = "\n".join(_generate_struct_field_assignments(target_struct.fields, structs, enums, "nested_item", bitmaps))
            field_assignments.append(f'''                {rust_field_name}: {{
                    if let Some(nested_tlv) = {item_var}.get(&[{field_id}]) {{
                        if let tlv::TlvItemValue::List(_) = nested_tlv {{
                            let nested_item = tlv::TlvItem {{ tag: {field_id}, value: nested_tlv.clone() }};
                            Some({struct_rust_name} {{
{nested_assignments_str}
                            }})
                        }} else {{
                            None
                        }}
                    }} else {{
                        None
                    }}
                }},''')
        elif field_type.endswith('Struct'):
            # Cross-cluster struct not in current cluster - skip this field
            pass
        else:
            # Default fallback
            field_assignments.append(f"                {rust_field_name}: {item_var}.get_int(&[{field_id}]).map(|v| v as u8),")

    return field_assignments


def _generate_single_field_encoding(
    field_id: int,
    rust_field: str,
    field_type: str,
    field_entry: Optional[str],
    value_path: str,
    structs: Dict[str, 'MatterStruct'],
    enums: Dict[str, 'MatterEnum'],
    bitmaps: Optional[Dict[str, 'MatterBitmap']] = None,
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
        bitmaps: Dictionary of bitmap definitions
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
        tlv_type = MatterType.get_tlv_type(field_type, bitmaps=bitmaps)
        cast = _get_value_cast_expr('x', field_type, enums, bitmaps)
        lines.append(f"{indent}if let Some(x) = {value_path}.{rust_field} {{ {fields_vec}.push(({field_id}, tlv::TlvItemValueEnc::{tlv_type}({cast})).into()); }}")
    elif field_type == 'list' and field_entry:
        # Handle list fields
        # Skip lists of cross-cluster struct references
        if field_entry.endswith('Struct') and (not structs or field_entry not in structs):
            return []  # Return empty list to signal skip
        entry_tlv = MatterType.get_tlv_type(field_entry, bitmaps=bitmaps)
        entry_rust = MatterType.get_rust_type(field_entry, enums=enums, bitmaps=bitmaps)
        if field_entry.endswith('Struct') and structs and field_entry in structs:
            nested = structs[field_entry]
            nested_lines = []
            for nf_id, nf_name, nf_type, nf_entry in nested.fields:
                nf_rust_field = escape_rust_keyword(convert_to_snake_case(nf_name))
                field_lines = _generate_single_field_encoding(
                    nf_id, nf_rust_field, nf_type, nf_entry, 'inner', structs, enums, bitmaps,
                    indent + "            ", 'nested_fields'
                )
                nested_lines.extend(field_lines)
            lines.append(f"{indent}if let Some(listv) = {value_path}.{rust_field} {{")
            lines.append(f"{indent}    let inner_vec: Vec<_> = listv.into_iter().map(|inner| {{")
            lines.append(f"{indent}        let mut nested_fields = Vec::new();")
            lines.extend(nested_lines)
            lines.append(f"{indent}        (0, tlv::TlvItemValueEnc::StructAnon(nested_fields)).into()")
            lines.append(f"{indent}    }}).collect();")
            lines.append(f"{indent}    {fields_vec}.push(({field_id}, tlv::TlvItemValueEnc::Array(inner_vec)).into());")
            lines.append(f"{indent}}}")
        elif entry_tlv == 'String':
            lines.append(f"{indent}if let Some(listv) = {value_path}.{rust_field} {{ {fields_vec}.push(({field_id}, tlv::TlvItemValueEnc::StructAnon(listv.into_iter().map(|x| (0, tlv::TlvItemValueEnc::String(x.clone())).into()).collect())).into()); }}")
        elif entry_tlv == 'OctetString':
            lines.append(f"{indent}if let Some(listv) = {value_path}.{rust_field} {{ {fields_vec}.push(({field_id}, tlv::TlvItemValueEnc::StructAnon(listv.into_iter().map(|x| (0, tlv::TlvItemValueEnc::OctetString(x.clone())).into()).collect())).into()); }}")
        elif entry_tlv == 'Bool':
            lines.append(f"{indent}if let Some(listv) = {value_path}.{rust_field} {{ {fields_vec}.push(({field_id}, tlv::TlvItemValueEnc::StructAnon(listv.into_iter().map(|x| (0, tlv::TlvItemValueEnc::Bool(x)).into()).collect())).into()); }}")
        elif entry_tlv.startswith('UInt') or entry_tlv.startswith('Int'):
            cast = _get_value_cast_expr('x', field_entry, enums, bitmaps)
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
                nf_id, nf_rust_field, nf_type, nf_entry, 'inner', structs, enums, bitmaps, indent + "    ", nested_vec_name
            )
            lines.extend(nested_lines)
        lines.append(f'{indent}    {fields_vec}.push(({field_id}, tlv::TlvItemValueEnc::StructInvisible({nested_vec_name})).into());')
        lines.append(f'{indent}}}')
    elif field_type.endswith('Struct'):
        # Cross-cluster struct - skip
        return []  # Return empty list to signal skip
    else:
        lines.append(f"{indent}// TODO: encoding for field {rust_field} ({field_type}) not implemented")

    return lines


def generate_field_tlv_encoding(field: 'MatterField', param_name: str, structs: Dict[str, 'MatterStruct'], enums: Optional[Dict[str, 'MatterEnum']] = None, bitmaps: Optional[Dict[str, 'MatterBitmap']] = None) -> str:
    """Generate TLV encoding line for a field.

    This function generates Rust code to encode a Matter field into TLV format.
    Moved from CommandField.get_tlv_encoding() to be field-type agnostic.

    Args:
        field: The MatterField to encode
        param_name: The Rust variable name holding the field value
        structs: Dictionary of struct definitions for encoding nested structs
        enums: Dictionary of enum definitions for proper type conversion
        bitmaps: Dictionary of bitmap definitions for proper type conversion

    Returns:
        String containing Rust code for encoding this field, or empty string if field should be skipped
    """
    if field.is_list:
        if field.entry_type:
            # Skip lists of cross-cluster struct references
            if field.entry_type.endswith('Struct') and (not structs or field.entry_type not in structs):
                return ""  # Skip this field
            # If the entry is a struct and we have its definition, generate
            # code that accepts `Vec<Struct>` and encodes each struct's
            # present fields into a TLV anonymous struct element.
            if field.entry_type.endswith('Struct') and structs and field.entry_type in structs:
                target = structs[field.entry_type]
                struct_rust_name = target.get_rust_struct_name()
                # Build per-field push statements for the inner struct
                inner_lines = []
                for f_id, f_name, f_type, f_entry in target.fields:
                    rust_field = escape_rust_keyword(convert_to_snake_case(f_name))
                    field_lines = _generate_single_field_encoding(
                        f_id, rust_field, f_type, f_entry, 'v', structs, enums, bitmaps,
                        "                    "
                    )
                    inner_lines.extend(field_lines)

                inner_body = "\n".join(inner_lines)
                # Generate the final map/collect expression with correct closure
                # Note: the opening brace after |v| opens the closure body
                closure_start = f"        ({field.id}, tlv::TlvItemValueEnc::Array({param_name}.into_iter().map(|v| " + "{\n"
                closure_end = "                }).collect())).into(),"
                return closure_start + "                    let mut fields = Vec::new();\n" + inner_body + "\n                    (0, tlv::TlvItemValueEnc::StructAnon(fields)).into()\n" + closure_end

            # Primitive entry types: map Matter TLV type to the correct
            # TlvItemValueEnc variant and cast elements to the appropriate
            # Rust type when needed.
            entry_tlv = MatterType.get_tlv_type(field.entry_type, bitmaps=bitmaps)
            entry_rust = MatterType.get_rust_type(field.entry_type, enums=enums, bitmaps=bitmaps)

            if entry_tlv == 'String':
                return f"        ({field.id}, tlv::TlvItemValueEnc::StructAnon({param_name}.into_iter().map(|v| (0, tlv::TlvItemValueEnc::String(v)).into()).collect())).into(),"
            if entry_tlv == 'OctetString':
                return f"        ({field.id}, tlv::TlvItemValueEnc::StructAnon({param_name}.into_iter().map(|v| (0, tlv::TlvItemValueEnc::OctetString(v)).into()).collect())).into(),"
            if entry_tlv == 'Bool':
                return f"        ({field.id}, tlv::TlvItemValueEnc::StructAnon({param_name}.into_iter().map(|v| (0, tlv::TlvItemValueEnc::Bool(v)).into()).collect())).into(),"
            if entry_tlv.startswith('UInt') or entry_tlv.startswith('Int'):
                # Cast numeric items to the target Rust type when necessary
                cast = _get_value_cast_expr('v', field.entry_type, enums, bitmaps)
                return f"        ({field.id}, tlv::TlvItemValueEnc::StructAnon({param_name}.into_iter().map(|v| (0, tlv::TlvItemValueEnc::{entry_tlv}({cast})).into()).collect())).into(),"

            # Fallback: preserve previous behavior but use the element as-is
            return f"        ({field.id}, tlv::TlvItemValueEnc::StructAnon({param_name}.into_iter().map(|v| (0, tlv::TlvItemValueEnc::UInt8(v)).into()).collect())).into(),"
        else:
            # No entry type specified — keep previous default (UInt8)
            return f"        ({field.id}, tlv::TlvItemValueEnc::StructAnon({param_name}.into_iter().map(|v| (0, tlv::TlvItemValueEnc::UInt8(v)).into()).collect())).into(),"

    tlv_type = MatterType.get_tlv_type(field.field_type, bitmaps=bitmaps)

    if field.nullable:
        # Handle nullable fields
        if field.field_type.endswith('Struct') and structs and field.field_type in structs:
            # Handle nullable struct fields - encode if Some, otherwise use empty struct
            struct_def = structs[field.field_type]
            lines = []
            lines.append(f"        // Encode optional struct {field.field_type}")
            lines.append(f"        let {param_name}_enc = if let Some(s) = {param_name} {{")
            lines.append(f"            let mut fields = Vec::new();")

            for f_id, f_name, f_type, f_entry in struct_def.fields:
                rust_field = escape_rust_keyword(convert_to_snake_case(f_name))
                field_lines = _generate_single_field_encoding(
                    f_id, rust_field, f_type, f_entry, 's', structs, enums, bitmaps, "            "
                )
                lines.extend(field_lines)

            lines.append(f"            tlv::TlvItemValueEnc::StructInvisible(fields)")
            lines.append(f"        }} else {{")
            lines.append(f"            tlv::TlvItemValueEnc::StructInvisible(Vec::new())")
            lines.append(f"        }};")
            lines.append(f"        ({field.id}, {param_name}_enc).into(),")
            return "\n".join(lines)
        elif field.field_type.endswith('Struct'):
            # Struct type not defined in this cluster - skip
            return ""

        # For Enum types, use proper conversion
        if field.field_type.endswith('Enum'):
            # Check if we have the enum definition
            if enums and field.field_type in enums:
                enum_name = enums[field.field_type].get_rust_enum_name()
                if field.default and field.default.lower() in ['null', 'none']:
                    # Use Default implementation for enum (should be first variant typically)
                    param_expr = f"{param_name}.map(|e| e.to_u8()).unwrap_or_default()"
                else:
                    default_value = field._get_default_value(enums, bitmaps)
                    param_expr = f"{param_name}.map(|e| e.to_u8()).unwrap_or({default_value})"
            else:
                # Fallback to u8 if enum not defined
                if field.default and field.default.lower() in ['null', 'none']:
                    param_expr = f"{param_name}.unwrap_or_default()"
                else:
                    default_value = field._get_default_value(enums, bitmaps)
                    param_expr = f"{param_name}.unwrap_or({default_value})"
        # For Bitmap types, use proper conversion
        elif field.field_type.endswith('Bitmap'):
            # Check if we have the bitmap definition
            if bitmaps and field.field_type in bitmaps:
                bitmap_name = bitmaps[field.field_type].get_rust_bitmap_name()
                if field.default and field.default.lower() in ['null', 'none']:
                    param_expr = f"{param_name}.unwrap_or_default()"
                else:
                    default_value = field._get_default_value(enums, bitmaps)
                    param_expr = f"{param_name}.unwrap_or({default_value})"
            else:
                # Fallback to u8 if bitmap not defined
                if field.default and field.default.lower() in ['null', 'none']:
                    param_expr = f"{param_name}.unwrap_or_default()"
                else:
                    default_value = field._get_default_value(enums, bitmaps)
                    param_expr = f"{param_name}.unwrap_or({default_value})"
        else:
            if field.default and field.default.lower() in ['null', 'none']:
                param_expr = f"{param_name}.unwrap_or_default()"
            else:
                default_value = field._get_default_value(enums, bitmaps)
                param_expr = f"{param_name}.unwrap_or({default_value})"

        return f"        ({field.id}, tlv::TlvItemValueEnc::{tlv_type}({param_expr})).into(),"
    else:
        # For non-nullable Enum types, use proper conversion
        if field.field_type.endswith('Enum'):
            # Check if we have the enum definition
            if enums and field.field_type in enums:
                param_expr = f"{param_name}.to_u8()"
            else:
                # Fallback: assume it's already u8
                param_expr = param_name
            return f"        ({field.id}, tlv::TlvItemValueEnc::{tlv_type}({param_expr})).into(),"
        # For non-nullable Bitmap types, use proper conversion
        elif field.field_type.endswith('Bitmap'):
            # Check if we have the bitmap definition
            if bitmaps and field.field_type in bitmaps:
                param_expr = param_name
            else:
                # Fallback: assume it's already the base type
                param_expr = param_name
            return f"        ({field.id}, tlv::TlvItemValueEnc::{tlv_type}({param_expr})).into(),"
        elif field.field_type.endswith('Struct') and structs and field.field_type in structs:
            # Single struct parameter - need to encode its fields
            struct_def = structs[field.field_type]
            lines = []
            lines.append(f"        // Encode struct {field.field_type}")

            # Extract base name for variable creation (strip any prefix like "params.")
            base_name = param_name.split('.')[-1] if '.' in param_name else param_name
            var_name = f"{base_name}_fields"

            lines.append(f"        let mut {var_name} = Vec::new();")

            # Track if any field is actually encoded (not TODO)
            has_encodable_fields = False

            for f_id, f_name, f_type, f_entry in struct_def.fields:
                rust_field = escape_rust_keyword(convert_to_snake_case(f_name))
                field_lines = _generate_single_field_encoding(
                    f_id, rust_field, f_type, f_entry, param_name, structs, enums, bitmaps,
                    "        ", var_name
                )
                # Check if this field is actually encodable (not a TODO comment)
                if field_lines and not any('TODO' in line for line in field_lines):
                    has_encodable_fields = True
                lines.extend(field_lines)

            # If no fields are encodable, suppress warnings and remove mut
            if not has_encodable_fields:
                lines.insert(0, f"        let _ = {param_name}; // Suppress unused warning - struct has no encodable fields")
                lines[2] = f"        let {var_name}: Vec<tlv::TlvItemEnc> = Vec::new();  // Empty struct"

            lines.append(f"        ({field.id}, tlv::TlvItemValueEnc::StructInvisible({var_name})).into(),")
            return "\n".join(lines)
        else:
            param_expr = param_name
            return f"        ({field.id}, tlv::TlvItemValueEnc::{tlv_type}({param_expr})).into(),"
