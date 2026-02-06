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

from .naming import convert_to_snake_case
from .xml_parser import ClusterParser
from .models import MatterStruct, AttributeField, MatterField


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
    if commands_with_fields or attributes or response_commands_with_fields or events_with_fields:
        imports += "use anyhow;\n"
    if attributes:
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
