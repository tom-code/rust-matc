"""
Orchestration functions for Matter cluster code generation.

This module contains high-level functions that coordinate the code generation
process: parsing XML files, generating Rust code, and creating module files.
"""

import xml.etree.ElementTree as ET
import os
import sys
import glob
import re
from typing import Dict, List

from .naming import convert_to_snake_case, upper_ident
from .xml_parser import ClusterParser
from .models import MatterStruct, AttributeField, MatterField
from .models.facade import emit_command_facade, emit_attribute_facade


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

        # Check if this is a list of octstr attribute
        if attribute.is_list and attribute.entry_type == 'octstr':
            # Use custom serialization for list of octstr
            match_arm = f'''        {clean_attr_id} => {{
            match {func_name}(tlv_value) {{
                Ok(value) => {{
                    // Serialize Vec<Vec<u8>> as array of hex strings
                    let hex_array: Vec<String> = value.iter()
                        .map(|bytes| bytes.iter()
                            .map(|byte| format!("{{:02x}}", byte))
                            .collect::<String>())
                        .collect();
                    serde_json::to_string(&hex_array).unwrap_or_else(|_| "null".to_string())
                }},
                Err(e) => format!("{{{{\\\"error\\\": \\\"{{}}\\\"}}}}", e),
            }}
        }}'''
        else:
            # Existing logic for other types
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
    response_commands = parser.parse_response_commands()
    events = parser.parse_events()
    structs = parser.parse_structs()
    enums = parser.parse_enums()
    bitmaps = parser.parse_bitmaps()

    # Detect name collisions between enums, structs, and bitmaps
    # If an enum/bitmap has the same name as a struct, rename by NOT removing the "Enum"/"Bitmap" suffix
    enum_names = {enum.get_rust_enum_name() for enum in enums.values()}
    struct_names = {struct.get_rust_struct_name() for struct in structs.values()}
    bitmap_names = {bitmap.get_rust_bitmap_name() for bitmap in bitmaps.values()}

    # Find collisions and keep track of which enums/bitmaps to preserve suffix
    enum_collisions = enum_names & struct_names
    bitmap_collisions = bitmap_names & (struct_names | enum_names)

    # Create new enums dict with adjusted names
    if enum_collisions:
        adjusted_enums = {}
        for enum_key, enum_obj in enums.items():
            if enum_obj.get_rust_enum_name() in enum_collisions:
                # Keep the original name with "Enum" suffix
                enum_obj._force_enum_suffix = True
            adjusted_enums[enum_key] = enum_obj
        enums = adjusted_enums

    # Create new bitmaps dict with adjusted names
    if bitmap_collisions:
        adjusted_bitmaps = {}
        for bitmap_key, bitmap_obj in bitmaps.items():
            if bitmap_obj.get_rust_bitmap_name() in bitmap_collisions:
                # Keep the original name with "Bitmap" suffix
                bitmap_obj._force_bitmap_suffix = True
            adjusted_bitmaps[bitmap_key] = bitmap_obj
        bitmaps = adjusted_bitmaps

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
        location_struct.add_field(MatterField(0, 'LocationName', 'string'))
        location_struct.add_field(MatterField(1, 'FloorNumber', 'uint16'))
        location_struct.add_field(MatterField(2, 'AreaType', 'uint8'))
        structs['LocationDescriptorStruct'] = location_struct

    # Generate header
    cluster_name_snake = parser.cluster_name.lower().replace(' ', '_').replace('-', '_')

    # Generate imports based on what we're generating
    imports = ""
    # Check if we have commands with fields (not field-less commands)
    commands_with_fields = [cmd for cmd in commands if cmd.fields]
    # Check if we have response commands with fields
    response_commands_with_fields = [resp for resp in response_commands if resp.fields]
    # Check if we have events with fields
    events_with_fields = [evt for evt in events if evt.fields]
    # tlv is only needed for commands, attributes, response commands, events, and structs (not enums)
    if commands_with_fields or attributes or response_commands_with_fields or events_with_fields or structs:
        imports += "use crate::tlv;\n"
    if commands_with_fields or commands or attributes or response_commands_with_fields or events_with_fields:
        imports += "use anyhow;\n"
    if attributes or commands:
        imports += "use serde_json;\n"

    # Check which specific serialization helpers are needed
    needs_opt_bytes_hex = False
    needs_opt_vec_bytes_hex = False

    if structs:
        for struct in structs.values():
            for field_id, field_name, field_type, entry_type in struct.fields:
                # Single octstr field needs serialize_opt_bytes_as_hex
                if field_type == 'octstr':
                    needs_opt_bytes_hex = True
                # List of octstr field needs serialize_opt_vec_bytes_as_hex
                elif field_type == 'list' and entry_type == 'octstr':
                    needs_opt_vec_bytes_hex = True

    # Also check response commands for octstr fields
    if response_commands:
        for response in response_commands:
            for field_id, field_name, field_type, entry_type in response.fields:
                if field_type == 'octstr':
                    needs_opt_bytes_hex = True
                elif field_type == 'list' and entry_type == 'octstr':
                    needs_opt_vec_bytes_hex = True

    # Also check events for octstr fields
    if events:
        for event in events:
            for field_id, field_name, field_type, entry_type in event.fields:
                if field_type == 'octstr':
                    needs_opt_bytes_hex = True
                elif field_type == 'list' and entry_type == 'octstr':
                    needs_opt_vec_bytes_hex = True

    code = f'''//! Matter TLV encoders and decoders for {parser.cluster_name}
//! Cluster ID: {parser.cluster_id}
//!
//! This file is automatically generated from {os.path.basename(xml_file)}

#![allow(clippy::too_many_arguments)]

{imports}

'''

    # Import only the specific serialization helpers that are needed
    if needs_opt_bytes_hex or needs_opt_vec_bytes_hex:
        helpers_to_import = []
        if needs_opt_bytes_hex:
            helpers_to_import.append('serialize_opt_bytes_as_hex')
        if needs_opt_vec_bytes_hex:
            helpers_to_import.append('serialize_opt_vec_bytes_as_hex')

        helpers_import = ', '.join(helpers_to_import)
        code += f'''// Import serialization helpers for octet strings
use crate::clusters::helpers::{{{helpers_import}}};

'''

    # Generate enum definitions (before structs as structs may use enums)
    if enums:
        code += "// Enum definitions\n\n"
        for enum in enums.values():
            code += enum.generate_rust_enum() + "\n\n"

    # Generate bitmap definitions (after enums, before structs)
    # Uses shared crate::clusters::bitmap::Bitmap<Tag, Base> type
    if bitmaps:
        code += "// Bitmap definitions\n\n"
        for bitmap in bitmaps.values():
            code += bitmap.generate_rust_bitmap() + "\n\n"

    # Generate struct definitions
    if structs:
        code += "// Struct definitions\n\n"
        for struct in structs.values():
            code += struct.generate_rust_struct(structs, enums, bitmaps) + "\n\n"

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
                code += command.generate_rust_function(structs, enums, bitmaps) + "\n\n"
                generated_functions.add(func_name)

    # Generate attribute decoders
    if attributes:
        code += "// Attribute decoders\n\n"
        generated_functions = set()
        for attribute in attributes:
            func_name = attribute.get_rust_function_name()
            if func_name not in generated_functions:
                code += attribute.generate_decode_function(structs, enums, bitmaps) + "\n\n"
                generated_functions.add(func_name)

        # Generate JSON dispatcher function
        code += generate_json_dispatcher_function(parser.cluster_id, attributes, structs)

        # Generate attribute list function
        code += generate_attribute_list_function(parser.cluster_id, attributes)

    # Generate command schema and JSON encoder
    if commands:
        code += generate_command_list_function(commands)
        code += generate_command_schema_function(commands, enums, bitmaps, structs)
        code += generate_command_json_encoder_function(commands, structs, enums, bitmaps)

    # Generate command response decoders
    if response_commands:
        # First generate response struct definitions
        response_structs_generated = set()
        for response in response_commands:
            if not response.fields:
                continue
            struct_name = response.get_rust_struct_name()
            if struct_name not in response_structs_generated:
                code += response.generate_rust_struct(structs, enums, bitmaps) + "\n\n"
                response_structs_generated.add(struct_name)

        # Then generate response decode functions
        if response_structs_generated:
            code += "// Command response decoders\n\n"
        generated_functions = set()
        for response in response_commands:
            if not response.fields:
                continue
            func_name = f"decode_{convert_to_snake_case(response.name)}"
            if func_name not in generated_functions:
                code += response.generate_decode_function(structs, enums, bitmaps) + "\n\n"
                generated_functions.add(func_name)

    # Generate typed facade (invokes + reads). Matches defs.rs constant naming
    # by using the <clusterIds><clusterId name=...> attribute, not the root
    # element's name attribute (which often has a " Cluster" suffix). When an
    # XML defines multiple clusters (e.g. ResourceMonitoring), gen2.py only
    # emits CLUSTER_{name}_ATTR_ID_ / CMD_ID_ constants for the LAST cluster,
    # so the facade must use the last clusterId too. Abstract/base clusters
    # (AlarmBase, ModeBase, ...) have <clusterId> with no id attribute and get
    # no defs constants - skip facade emission for those files.
    facade_cluster_name = None
    cluster_ids_elem = parser.root.find('clusterIds')
    if cluster_ids_elem is not None:
        concrete_ids = [ci for ci in cluster_ids_elem.findall('clusterId') if ci.get('id')]
        if concrete_ids:
            facade_cluster_name = concrete_ids[-1].get('name')

    if facade_cluster_name:
        cluster_upper = upper_ident(facade_cluster_name)

        response_by_name = {resp.name: resp for resp in response_commands}

        facade_code = ""
        emitted_fns = set()
        for command in commands:
            fn_name = f"cmd:{command.name}"
            if fn_name in emitted_fns:
                continue
            emitted_fns.add(fn_name)
            facade_code += emit_command_facade(
                command, cluster_upper, facade_cluster_name,
                structs, enums, bitmaps, response_by_name,
            )

        emitted_attr_fns = set()
        for attribute in attributes:
            key = f"attr:{attribute.name}"
            if key in emitted_attr_fns:
                continue
            emitted_attr_fns.add(key)
            facade_code += emit_attribute_facade(
                attribute, cluster_upper, facade_cluster_name,
                structs, enums, bitmaps,
            )

        if facade_code:
            code += "// Typed facade (invokes + reads)\n\n"
            code += facade_code

    # Generate event decoders
    if events:
        # First generate event struct definitions
        event_structs_generated = set()
        for event in events:
            if not event.fields:
                continue
            struct_name = event.get_rust_struct_name()
            if struct_name not in event_structs_generated:
                code += event.generate_rust_struct(structs, enums, bitmaps) + "\n\n"
                event_structs_generated.add(struct_name)

        # Then generate event decode functions
        if event_structs_generated:
            code += "// Event decoders\n\n"
        generated_functions = set()
        for event in events:
            if not event.fields:
                continue
            func_name = f"decode_{convert_to_snake_case(event.name)}_event"
            if func_name not in generated_functions:
                code += event.generate_decode_function(structs, enums, bitmaps) + "\n\n"
                generated_functions.add(func_name)

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


def _generate_cluster_dispatcher(cluster_info: List[Dict[str, str]], dispatcher_type: str) -> str:
    """Generate a cluster dispatcher function (either command or attribute).

    Args:
        cluster_info: List of cluster information dictionaries
        dispatcher_type: Either "command" or "attribute"

    Returns:
        Generated dispatcher function code
    """
    if dispatcher_type == "command":
        function_name = "decode_attribute_json"
        function_call = "decode_attribute_json(cluster_id, attribute_id, tlv_value)"
        doc_title = "Main dispatcher function for decoding attributes to JSON"
        doc_desc = """This function routes to the appropriate cluster-specific decoder based on cluster ID.
///
/// # Parameters
/// * `cluster_id` - The cluster identifier
/// * `attribute_id` - The attribute identifier
/// * `tlv_value` - The TLV value to decode
///
/// # Returns
/// JSON string representation of the decoded value or error message"""
        signature = "pub fn decode_attribute_json(cluster_id: u32, attribute_id: u32, tlv_value: &crate::tlv::TlvItemValue) -> String"
        error_msg = 'format!("{{\\\"error\\\": \\\"Unsupported cluster ID: {}\\\"}}", cluster_id)'
    else:  # attribute
        function_name = "get_attribute_list"
        function_call = "get_attribute_list()"
        doc_title = "Main dispatcher function for getting attribute lists"
        doc_desc = """This function routes to the appropriate cluster-specific attribute list based on cluster ID.
///
/// # Parameters
/// * `cluster_id` - The cluster identifier
///
/// # Returns
/// Vector of tuples containing (attribute_id, attribute_name) or empty vector if unsupported"""
        signature = "pub fn get_attribute_list(cluster_id: u32) -> Vec<(u32, &'static str)>"
        error_msg = "vec![]"

    # Build match arms for each cluster that has attributes, avoiding duplicates
    seen_cluster_ids = set()
    match_arms = []

    for info in sorted(cluster_info, key=lambda x: x['cluster_id']):
        if info['has_attributes'] and info['cluster_id'] not in seen_cluster_ids:
            match_arms.append(f"        {info['cluster_id']} => {info['module_name']}::{function_call},")
            seen_cluster_ids.add(info['cluster_id'])
    match_arms_str = '\n'.join(match_arms)

    dispatcher_function = f'''
/// {doc_title}
///
/// {doc_desc}
{signature} {{
    match cluster_id {{
{match_arms_str}
        _ => {error_msg},
    }}
}}
'''

    return dispatcher_function


def generate_main_dispatcher(cluster_info: List[Dict[str, str]]) -> str:
    """Generate the main decode_attribute_json dispatcher function."""
    return _generate_cluster_dispatcher(cluster_info, "command")


def generate_main_attribute_list_dispatcher(cluster_info: List[Dict[str, str]]) -> str:
    """Generate the main get_attribute_list dispatcher function."""
    return _generate_cluster_dispatcher(cluster_info, "attribute")


# ---------------------------------------------------------------------------
# Command schema / JSON encoder generation helpers
# ---------------------------------------------------------------------------

# Map from Matter type to FieldKind variant name (unit variants).
_SCALAR_FIELD_KIND = {
    'uint8':        'U8',
    'uint16':       'U16',
    'uint32':       'U32',
    'uint64':       'U64',
    'int8':         'I8',
    'int16':        'I16',
    'int32':        'I32',
    'int64':        'I64',
    'bool':         'Bool',
    'string':       'String',
    'octstr':       'OctetString',
    # Specialised Matter numeric aliases -> closest scalar
    'epoch-s':      'U64',
    'epoch-us':     'U64',
    'elapsed-s':    'U32',
    'power-mW':     'U32',
    'energy-mWh':   'U64',
    'temperature':  'I16',
    'devtype-id':   'U32',
    'cluster-id':   'U32',
    'endpoint-no':  'U16',
    'node-id':      'U64',
    'vendor-id':    'U16',
    'subject-id':   'U64',
    'SubjectID':    'U64',
    'attribute-id': 'U32',
    'enum8':        'U8',
    'enum16':       'U16',
    'bitmap8':      'U8',
    'bitmap16':     'U16',
    'bitmap32':     'U32',
}


def _matter_type_to_field_kind_expr(field, enums, bitmaps) -> str:
    """Return a Rust FieldKind expression string for the given MatterField."""
    from .models.enums import MatterEnum, MatterBitmap
    from .naming import convert_to_snake_case, escape_rust_keyword

    ft = field.field_type
    if ft == 'list':
        et = field.entry_type or 'uint8'
        return f'crate::clusters::codec::FieldKind::List {{ entry_type: "{et}" }}'

    if ft.endswith('Enum') and enums and ft in enums:
        enum_obj = enums[ft]
        rust_name = enum_obj.get_rust_enum_name()
        # Emit variants inline as static slice (const-promotable literals).
        variants = ", ".join(
            f'({v}, "{n}")' for v, n, _ in enum_obj.items
        )
        return (
            f'crate::clusters::codec::FieldKind::Enum {{ '
            f'name: "{rust_name}", '
            f'variants: &[{variants}] }}'
        )

    if ft.endswith('Bitmap') and bitmaps and ft in bitmaps:
        bmp = bitmaps[ft]
        rust_name = bmp.get_rust_bitmap_name()
        bits = ", ".join(
            f'({1 << bp}, "{n}")' for bp, n, _ in bmp.bitfields
        )
        return (
            f'crate::clusters::codec::FieldKind::Bitmap {{ '
            f'name: "{rust_name}", '
            f'bits: &[{bits}] }}'
        )

    if ft.endswith('Struct'):
        return f'crate::clusters::codec::FieldKind::Struct {{ name: "{ft}" }}'

    # Generic enum/bitmap without local definition -> scalar fallback
    if ft.endswith('Enum'):
        return 'crate::clusters::codec::FieldKind::U8'
    if ft.endswith('Bitmap'):
        return 'crate::clusters::codec::FieldKind::U8'

    kind = _SCALAR_FIELD_KIND.get(ft, 'U32')
    return f'crate::clusters::codec::FieldKind::{kind}'


def _field_has_complex_type(field, structs) -> bool:
    """True if the field can't be encoded by the simple JSON encoder (v1)."""
    # Any list field is complex for v1 (even list of primitives).
    if field.field_type == 'list':
        return True
    if field.field_type.endswith('Struct') and structs and field.field_type in structs:
        return True
    return False


def _command_has_complex_fields(command, structs) -> bool:
    """True if any visible (non-cross-cluster-skipped) field is complex."""
    for f in command.fields:
        # Skip cross-cluster struct refs the same way render_params does.
        if f.field_type == 'list' and f.entry_type and f.entry_type.endswith('Struct') and (not structs or f.entry_type not in structs):
            continue
        if not f.field_type == 'list' and f.field_type.endswith('Struct') and (not structs or f.field_type not in structs):
            continue
        if _field_has_complex_type(f, structs):
            return True
    return False


# Map Matter type -> (get_fn, cast_suffix) for optional and mandatory extraction.
# cast_suffix is what to append after the extracted u64/i64 value.
_JSON_EXTRACT = {
    'uint8':        ('get_u8',   ''),
    'uint16':       ('get_u16',  ''),
    'uint32':       ('get_u32',  ''),
    'uint64':       ('get_u64',  ''),
    'int8':         ('get_i8',   ''),
    'int16':        ('get_i16',  ''),
    'int32':        ('get_i32',  ''),
    'int64':        ('get_i64',  ''),
    'bool':         ('get_bool', ''),
    'string':       ('get_string', ''),
    'octstr':       ('get_octstr', ''),
    'epoch-s':      ('get_u64',  ''),
    'epoch-us':     ('get_u64',  ''),
    'elapsed-s':    ('get_u32',  ''),
    'power-mW':     ('get_u32',  ''),
    'energy-mWh':   ('get_u64',  ''),
    'temperature':  ('get_i16',  ''),
    'devtype-id':   ('get_u32',  ''),
    'cluster-id':   ('get_u32',  ''),
    'endpoint-no':  ('get_u16',  ''),
    'node-id':      ('get_u64',  ''),
    'vendor-id':    ('get_u16',  ''),
    'subject-id':   ('get_u64',  ''),
    'SubjectID':    ('get_u64',  ''),
    'attribute-id': ('get_u32',  ''),
    'enum8':        ('get_u8',   ''),
    'enum16':       ('get_u16',  ''),
    'bitmap8':      ('get_u8',   ''),
    'bitmap16':     ('get_u16',  ''),
    'bitmap32':     ('get_u32',  ''),
}


_RUST_SCALAR_TO_EXTRACT = {
    'u8':      'get_u8',
    'u16':     'get_u16',
    'u32':     'get_u32',
    'u64':     'get_u64',
    'i8':      'get_i8',
    'i16':     'get_i16',
    'i32':     'get_i32',
    'i64':     'get_i64',
    'bool':    'get_bool',
    'String':  'get_string',
    'Vec<u8>': 'get_octstr',
}


def _generate_field_json_extraction(param_name: str, rust_type: str, field, enums, bitmaps) -> str:
    """
    Return a Rust let-binding that extracts one field from the JSON `args`.
    Dispatches on `rust_type` (the Rust type from render_params) so the
    extracted value always matches what the encode_* function expects.
    """
    json_key = field.get_rust_param_name()

    # Unwrap Option<T>
    is_opt = rust_type.startswith('Option<')
    inner_type = rust_type[7:-1] if is_opt else rust_type
    opt_prefix = 'opt_' if is_opt else ''

    # --- simple scalar types ---
    if inner_type in _RUST_SCALAR_TO_EXTRACT:
        base_fn = _RUST_SCALAR_TO_EXTRACT[inner_type]
        get_fn = base_fn.replace('get_', f'get_{opt_prefix}')
        return f'let {param_name} = crate::clusters::codec::json_util::{get_fn}(args, "{json_key}")?;'

    # --- enum types (named Rust enum, not a primitive) ---
    if enums:
        for eobj in enums.values():
            if eobj.get_rust_enum_name() == inner_type:
                if is_opt:
                    return (
                        f'let {param_name} = crate::clusters::codec::json_util::get_opt_u64(args, "{json_key}")?\n'
                        f'            .and_then(|n| {inner_type}::from_u8(n as u8));'
                    )
                else:
                    return (
                        f'let {param_name} = {{\n'
                        f'            let n = crate::clusters::codec::json_util::get_u64(args, "{json_key}")?;\n'
                        f'            {inner_type}::from_u8(n as u8).ok_or_else(|| anyhow::anyhow!("invalid {inner_type}: {{}}", n))?\n'
                        f'        }};'
                    )

    # --- bitmap types (type aliases to numeric) ---
    if bitmaps:
        for bobj in bitmaps.values():
            if bobj.get_rust_bitmap_name() == inner_type:
                base_type = bobj.get_base_type()
                get_fn = f'get_{opt_prefix}{base_type}'
                return f'let {param_name} = crate::clusters::codec::json_util::{get_fn}(args, "{json_key}")?;'

    # --- fallback: treat as u32 (handles unknown bitmap aliases, etc.) ---
    get_fn = f'get_{opt_prefix}u32'
    return f'let {param_name} = crate::clusters::codec::json_util::{get_fn}(args, "{json_key}")?;'


def generate_command_list_function(commands) -> str:
    """Generate get_command_list() and get_command_name() for one cluster."""
    if not commands:
        return ''

    seen: set = set()
    entries = []
    for cmd in commands:
        if cmd.id not in seen:
            seen.add(cmd.id)
            entries.append((cmd.id, cmd.name))

    if not entries:
        return ''

    list_lines = '\n'.join(f'        ({cid}, "{cname}"),' for cid, cname in entries)
    name_arms = '\n'.join(f'        {cid} => Some("{cname}"),' for cid, cname in entries)

    return f'''// Command listing

pub fn get_command_list() -> Vec<(u32, &'static str)> {{
    vec![
{list_lines}
    ]
}}

pub fn get_command_name(cmd_id: u32) -> Option<&'static str> {{
    match cmd_id {{
{name_arms}
        _ => None,
    }}
}}

'''


def generate_command_schema_function(commands, enums, bitmaps, structs) -> str:
    """Generate get_command_schema() for one cluster."""
    if not commands:
        return ''

    seen: set = set()
    arms = []
    for cmd in commands:
        if cmd.id in seen:
            continue
        seen.add(cmd.id)

        # Filter fields the same way render_params does (skip cross-cluster struct refs).
        visible_fields = []
        for f in cmd.fields:
            if f.is_list and f.entry_type and f.entry_type.endswith('Struct') and (not structs or f.entry_type not in structs):
                continue
            if not f.is_list and f.field_type.endswith('Struct') and (not structs or f.field_type not in structs):
                continue
            visible_fields.append(f)

        if not visible_fields:
            arms.append(f'        {cmd.id} => Some(vec![]),')
            continue

        field_constructors = []
        for f in visible_fields:
            kind_expr = _matter_type_to_field_kind_expr(f, enums, bitmaps)
            opt_str = 'true' if not f.mandatory else 'false'
            null_str = 'true' if f.nullable else 'false'
            field_constructors.append(
                f'            crate::clusters::codec::CommandField {{ '
                f'tag: {f.id}, '
                f'name: "{f.get_rust_param_name()}", '
                f'kind: {kind_expr}, '
                f'optional: {opt_str}, '
                f'nullable: {null_str} }},'
            )
        fields_str = '\n'.join(field_constructors)
        arms.append(f'        {cmd.id} => Some(vec![\n{fields_str}\n        ]),')

    arms_str = '\n'.join(arms)

    return f'''pub fn get_command_schema(cmd_id: u32) -> Option<Vec<crate::clusters::codec::CommandField>> {{
    match cmd_id {{
{arms_str}
        _ => None,
    }}
}}

'''


def generate_command_json_encoder_function(commands, structs, enums, bitmaps) -> str:
    """Generate encode_command_json() for one cluster."""
    if not commands:
        return ''

    seen: set = set()
    arms = []
    for cmd in commands:
        if cmd.id in seen:
            continue
        seen.add(cmd.id)

        if not cmd.fields:
            # No fields -> empty payload
            arms.append(f'        {cmd.id} => Ok(vec![]),')
            continue

        if _command_has_complex_fields(cmd, structs):
            arms.append(
                f'        {cmd.id} => Err(anyhow::anyhow!('
                f'"command \\\"{cmd.name}\\\" has complex args: use raw mode")),'
            )
            continue

        # Build extraction lines + call to encode_*
        from .models.commands import MatterCommand
        param_fields, use_param_struct, struct_name = cmd.render_params(structs, enums, bitmaps)

        extract_lines = []
        for (pname, ptype), field in zip(param_fields, [
            f for f in cmd.fields
            if not (f.is_list and f.entry_type and f.entry_type.endswith('Struct') and (not structs or f.entry_type not in structs))
            and not (not f.is_list and f.field_type.endswith('Struct') and (not structs or f.field_type not in structs))
        ]):
            extract_lines.append(
                '        ' + _generate_field_json_extraction(pname, ptype, field, enums, bitmaps)
            )

        extract_str = '\n'.join(extract_lines)
        func_name = cmd.get_rust_function_name()

        if use_param_struct:
            struct_fields = '\n'.join(f'                {n}: {n},' for n, _ in param_fields)
            call = (
                f'        let params = {struct_name} {{\n'
                f'{struct_fields}\n'
                f'        }};\n'
                f'        {func_name}(params)'
            )
        else:
            call_args = ', '.join(n for n, _ in param_fields)
            call = f'        {func_name}({call_args})'

        arms.append(
            f'        {cmd.id} => {{\n'
            f'{extract_str}\n'
            f'{call}\n'
            f'        }}'
        )

    arms_str = '\n'.join(arms)

    # Use _args when no arm reads from args (avoids unused variable warning).
    # Check for the actual call pattern, not just the string "args".
    uses_args = any('json_util::get' in arm for arm in arms)
    args_param = 'args' if uses_args else '_args'

    return f'''pub fn encode_command_json(cmd_id: u32, {args_param}: &serde_json::Value) -> anyhow::Result<Vec<u8>> {{
    match cmd_id {{
{arms_str}
        _ => Err(anyhow::anyhow!("unknown command ID: 0x{{:02X}}", cmd_id)),
    }}
}}

'''


def _generate_command_dispatchers(cluster_info: List[Dict]) -> str:
    """Generate cross-cluster command dispatchers for mod.rs."""
    seen: set = set()
    list_arms = []
    name_arms = []
    schema_arms = []
    encoder_arms = []

    for info in sorted(cluster_info, key=lambda x: x['cluster_id']):
        cid = info['cluster_id']
        mod = info['module_name']
        if not info.get('has_commands', False) or cid in seen:
            continue
        seen.add(cid)
        list_arms.append(f'        {cid} => {mod}::get_command_list(),')
        name_arms.append(f'        {cid} => {mod}::get_command_name(cmd_id),')
        schema_arms.append(f'        {cid} => {mod}::get_command_schema(cmd_id),')
        encoder_arms.append(f'        {cid} => {mod}::encode_command_json(cmd_id, args),')

    list_arms_str = '\n'.join(list_arms)
    name_arms_str = '\n'.join(name_arms)
    schema_arms_str = '\n'.join(schema_arms)
    encoder_arms_str = '\n'.join(encoder_arms)

    return f'''
pub fn get_command_list(cluster_id: u32) -> Vec<(u32, &'static str)> {{
    match cluster_id {{
{list_arms_str}
        _ => vec![],
    }}
}}

pub fn get_command_name(cluster_id: u32, cmd_id: u32) -> Option<&'static str> {{
    match cluster_id {{
{name_arms_str}
        _ => None,
    }}
}}

pub fn get_command_schema(cluster_id: u32, cmd_id: u32) -> Option<Vec<CommandField>> {{
    match cluster_id {{
{schema_arms_str}
        _ => None,
    }}
}}

pub fn encode_command_json(cluster_id: u32, cmd_id: u32, args: &serde_json::Value) -> anyhow::Result<Vec<u8>> {{
    match cluster_id {{
{encoder_arms_str}
        _ => Err(anyhow::anyhow!("unsupported cluster: 0x{{:04X}}", cluster_id)),
    }}
}}
'''


_SCHEMA_RS = '''\
// Shared types for runtime-introspectable command schemas.
// Referenced by generated per-cluster codec files and by matc consumers.

#[derive(Clone, Debug, serde::Serialize)]
pub struct CommandField {
    pub tag: u32,
    pub name: &\'static str,
    pub kind: FieldKind,
    pub optional: bool,
    pub nullable: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FieldKind {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    Bool,
    String,
    OctetString,
    Enum {
        name: &\'static str,
        variants: &\'static [(u32, &\'static str)],
    },
    Bitmap {
        name: &\'static str,
        bits: &\'static [(u32, &\'static str)],
    },
    Struct {
        name: &\'static str,
    },
    List {
        entry_type: &\'static str,
    },
}
'''

_JSON_UTIL_RS = '''\
// Helper functions for extracting typed values from serde_json::Value objects
// used by the generated encode_command_json functions.

use anyhow;

pub fn get_u8(args: &serde_json::Value, name: &str) -> anyhow::Result<u8> {
    args.get(name)
        .and_then(|v| v.as_u64())
        .map(|n| n as u8)
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

pub fn get_u16(args: &serde_json::Value, name: &str) -> anyhow::Result<u16> {
    args.get(name)
        .and_then(|v| v.as_u64())
        .map(|n| n as u16)
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

pub fn get_u32(args: &serde_json::Value, name: &str) -> anyhow::Result<u32> {
    args.get(name)
        .and_then(|v| v.as_u64())
        .map(|n| n as u32)
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

pub fn get_u64(args: &serde_json::Value, name: &str) -> anyhow::Result<u64> {
    args.get(name)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

pub fn get_i8(args: &serde_json::Value, name: &str) -> anyhow::Result<i8> {
    args.get(name)
        .and_then(|v| v.as_i64())
        .map(|n| n as i8)
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

pub fn get_i16(args: &serde_json::Value, name: &str) -> anyhow::Result<i16> {
    args.get(name)
        .and_then(|v| v.as_i64())
        .map(|n| n as i16)
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

pub fn get_i32(args: &serde_json::Value, name: &str) -> anyhow::Result<i32> {
    args.get(name)
        .and_then(|v| v.as_i64())
        .map(|n| n as i32)
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

pub fn get_i64(args: &serde_json::Value, name: &str) -> anyhow::Result<i64> {
    args.get(name)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

pub fn get_bool(args: &serde_json::Value, name: &str) -> anyhow::Result<bool> {
    args.get(name)
        .and_then(|v| v.as_bool())
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

pub fn get_string(args: &serde_json::Value, name: &str) -> anyhow::Result<String> {
    args.get(name)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

// Accepts a hex string and decodes it to bytes.
pub fn get_octstr(args: &serde_json::Value, name: &str) -> anyhow::Result<Vec<u8>> {
    let s = args.get(name)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))?;
    let s = s.replace(\' \', "");
    hex::decode(&s).map_err(|e| anyhow::anyhow!("field {}: invalid hex: {}", name, e))
}

// Optional variants - return None when the field is absent or null.
pub fn get_opt_u8(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<u8>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_u64()
            .map(|n| Some(n as u8))
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_u16(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<u16>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_u64()
            .map(|n| Some(n as u16))
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_u32(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<u32>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_u64()
            .map(|n| Some(n as u32))
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_u64(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<u64>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_u64()
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_i8(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<i8>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_i64()
            .map(|n| Some(n as i8))
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_i16(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<i16>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_i64()
            .map(|n| Some(n as i16))
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_i32(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<i32>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_i64()
            .map(|n| Some(n as i32))
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_i64(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<i64>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_i64()
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_bool(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<bool>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_bool()
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_string(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<String>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_str()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_octstr(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => {
            let s = v.as_str().ok_or_else(|| anyhow::anyhow!("invalid field: {}", name))?;
            let s = s.replace(\' \', "");
            hex::decode(&s)
                .map(Some)
                .map_err(|e| anyhow::anyhow!("field {}: invalid hex: {}", name, e))
        }
    }
}
'''


def generate_support_files(output_dir: str) -> None:
    """Write schema.rs and json_util.rs into output_dir."""
    for filename, content in (('schema.rs', _SCHEMA_RS), ('json_util.rs', _JSON_UTIL_RS)):
        path = os.path.join(output_dir, filename)
        with open(path, 'w') as f:
            f.write(content)
        print(f"  + Wrote {filename}")


def generate_mod_file(output_dir: str, rust_files: List[str], cluster_info: List[Dict[str, str]]) -> None:
    """Generate a mod.rs file that includes all generated modules."""
    mod_file_path = os.path.join(output_dir, "mod.rs")

    with open(mod_file_path, 'w') as f:
        f.write("//! Matter cluster TLV encoders and decoders\n")
        f.write("//! \n")
        f.write("//! This file is automatically generated.\n\n")

        f.write("pub mod schema;\n")
        f.write("pub mod json_util;\n")
        f.write("pub use schema::{CommandField, FieldKind};\n\n")

        # Generated module declarations
        for rust_file in sorted(rust_files):
            module_name = generate_module_name(rust_file)
            f.write(f"pub mod {module_name};\n")

        # Attribute dispatchers (existing)
        f.write("\n")
        f.write(generate_main_dispatcher(cluster_info))

        f.write("\n")
        f.write(generate_main_attribute_list_dispatcher(cluster_info))

        # Command dispatchers (new)
        f.write("\n")
        f.write(_generate_command_dispatchers(cluster_info))

    print(f"  ✓ Generated mod.rs with {len(rust_files)} modules and dispatchers")


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

            # Check if cluster has commandToServer commands
            commands_elem = root.find('commands')
            has_commands = False
            if commands_elem is not None:
                has_commands = any(
                    cmd.get('direction', 'commandToServer') == 'commandToServer'
                    for cmd in commands_elem.findall('command')
                )

            cluster_info.append({
                'cluster_id': cluster_id,
                'module_name': module_name,
                'has_attributes': has_attributes,
                'has_commands': has_commands,
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

    # Write support files and mod.rs
    if generated_rust_files:
        generate_support_files(output_dir)
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
