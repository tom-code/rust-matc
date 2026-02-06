"""
Name and type conversion utilities for Matter code generation.

This module provides functions for converting between naming conventions
(CamelCase, snake_case, PascalCase) and handling Rust keyword escaping.
"""

import re
from typing import Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from type_mapping import MatterType
    from models.enums import MatterEnum


# Set of numeric and ID types in Matter specification
# Derived from TYPE_MAP - includes all types that map to integer Rust types
# This includes both ID types (devtype-id, cluster-id, etc.) and base enum/bitmap types (enum8, enum16, bitmap8, etc.)
def _build_numeric_or_id_types():
    """Build set of numeric/ID types from TYPE_MAP."""
    from .type_mapping import MatterType
    numeric_types = set()
    # Exclude only non-numeric primitive types and the bare integer types handled by prefix check
    excluded = {'bool', 'string', 'octstr', 'list',
                'uint8', 'uint16', 'uint32', 'uint64',
                'int8', 'int16', 'int32', 'int64'}

    for matter_type, (tlv_type, rust_type) in MatterType.TYPE_MAP.items():
        # Include all types that map to integer Rust types (including enum8, enum16, bitmap8, etc.)
        if matter_type not in excluded and rust_type and rust_type.startswith(('u', 'i')):
            numeric_types.add(matter_type)

    return numeric_types

NUMERIC_OR_ID_TYPES = _build_numeric_or_id_types()


def is_numeric_or_id_type(t: str) -> bool:
    """Return True if the Matter type is numeric or a well-known ID type."""
    return t.startswith('uint') or t.startswith('int') or t in NUMERIC_OR_ID_TYPES


def build_numeric_field_assignment(
    var_name: str,
    field_id: int,
    matter_type: str,
    enums: Optional[Dict[str, 'MatterEnum']] = None,
    indent: str = '                ',
    item_var: str = 'item'
) -> str:
    """Generate Rust code snippet for assigning a numeric/ID field with proper casting."""
    # Import here to avoid circular dependency at module load time
    from .type_mapping import MatterType

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


def convert_to_pascal_case(name: str) -> str:
    """
    Convert a name (either already PascalCase or snake_case) to PascalCase.

    Examples:
    - SolicitOffer -> SolicitOffer (already PascalCase)
    - solicit_offer -> SolicitOffer
    """
    # If already PascalCase (first letter uppercase), return as-is
    if name and name[0].isupper():
        return name

    # Convert from snake_case to PascalCase
    return ''.join(word.capitalize() for word in name.split('_'))


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


def is_cross_cluster_struct(field_type: str, structs: Optional[Dict] = None) -> bool:
    """
    Check if a field type is a cross-cluster struct reference.

    A cross-cluster struct is a struct type that ends with 'Struct' but is not
    defined in the current cluster's struct dictionary.

    Args:
        field_type: The Matter type string to check
        structs: Dictionary of struct definitions for the current cluster

    Returns:
        True if this is a cross-cluster struct reference, False otherwise
    """
    return field_type.endswith('Struct') and structs is not None and field_type not in structs


def should_skip_field(
    field_type: str,
    entry_type: Optional[str],
    structs: Optional[Dict] = None
) -> bool:
    """
    Determine if a field should be skipped during struct generation.

    Fields are skipped if they reference cross-cluster structs that aren't
    defined in the current cluster.

    Args:
        field_type: The field's Matter type
        entry_type: For list fields, the type of list entries
        structs: Dictionary of struct definitions for the current cluster

    Returns:
        True if the field should be skipped, False otherwise
    """
    # Skip fields with undefined cross-cluster struct types
    if is_cross_cluster_struct(field_type, structs):
        return True

    # Skip lists of cross-cluster struct references
    if field_type == 'list' and entry_type and is_cross_cluster_struct(entry_type, structs):
        return True

    return False
