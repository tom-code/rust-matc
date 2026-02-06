"""
Matter type to Rust type mapping.

This module provides the MatterType class which handles conversion between
Matter specification types and their Rust/TLV equivalents.
"""

from typing import Dict, TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from models.enums import MatterEnum, MatterBitmap


class MatterType:
    """Represents a Matter data type and its Rust TLV encoding equivalent."""

    # Unified type mapping: Matter type -> (TLV type, Rust type)
    TYPE_MAP = {
        'uint8':        ('UInt8',       'u8'),
        'uint16':       ('UInt16',      'u16'),
        'uint32':       ('UInt32',      'u32'),
        'uint64':       ('UInt64',      'u64'),
        'int8':         ('Int8',        'i8'),
        'int16':        ('Int16',       'i16'),
        'int32':        ('Int32',       'i32'),
        'int64':        ('Int64',       'i64'),
        'bool':         ('Bool',        'bool'),
        'string':       ('String',      'String'),
        'epoch-s':      ('UInt64',      'u64'),
        'epoch-us':     ('UInt64',      'u64'),
        'elapsed-s':    ('UInt32',      'u32'),
        'power-mW':     ('UInt32',      'u32'),
        'energy-mWh':   ('UInt64',      'u64'),
        'temperature':  ('Int16',       'i16'),
        'octstr':       ('OctetString', 'Vec<u8>'),
        'list':         ('StructAnon',  None),
        # Matter-specific ID types
        'devtype-id':   ('UInt32',      'u32'),
        'cluster-id':   ('UInt32',      'u32'),
        'endpoint-no':  ('UInt16',      'u16'),
        'node-id':      ('UInt64',      'u64'),
        'vendor-id':    ('UInt16',      'u16'),
        'subject-id':   ('UInt64',      'u64'),
        'SubjectID':    ('UInt64',      'u64'),
        'attribute-id': ('UInt32',      'u32'),
        # Enum/Bitmap base types (for xml_to_readable.py compatibility)
        'enum8':        ('UInt8',       'u8'),
        'enum16':       ('UInt16',      'u16'),
        'bitmap8':      ('UInt8',       'u8'),
        'bitmap16':     ('UInt16',      'u16'),
        'bitmap32':     ('UInt32',      'u32'),
    }

    # Backward compatibility: old TYPE_MAPPING is now derived from TYPE_MAP
    TYPE_MAPPING = {k: v[0] for k, v in TYPE_MAP.items()}

    # Derived inverse mappings for TLV <-> Rust conversions
    TLV_TO_RUST = {
        'UInt8': 'u8', 'UInt16': 'u16', 'UInt32': 'u32', 'UInt64': 'u64',
        'Int8': 'i8', 'Int16': 'i16', 'Int32': 'i32', 'Int64': 'i64',
    }

    RUST_TO_TLV = {
        'u8': 'UInt8', 'u16': 'UInt16', 'u32': 'UInt32', 'u64': 'UInt64',
        'i8': 'Int8', 'i16': 'Int16', 'i32': 'Int32', 'i64': 'Int64',
    }

    @classmethod
    def get_tlv_type(cls, matter_type: str, bitmaps: Optional[Dict[str, 'MatterBitmap']] = None) -> str:
        """Convert Matter type to TLV encoding type."""
        # Handle special cases
        if matter_type.endswith('Enum'):
            return 'UInt8'
        if matter_type.endswith('Bitmap'):
            if bitmaps and matter_type in bitmaps:
                base_type = bitmaps[matter_type].get_base_type()
                # Use RUST_TO_TLV mapping instead of if/elif chain
                return cls.RUST_TO_TLV.get(base_type, 'UInt8')
            return 'UInt8'

        return cls.TYPE_MAPPING.get(matter_type, 'UInt8')

    @classmethod
    def get_rust_type(cls, matter_type: str, is_list: bool = False, enums: Optional[Dict[str, 'MatterEnum']] = None, bitmaps: Optional[Dict[str, 'MatterBitmap']] = None) -> str:
        """Get the corresponding Rust type for function parameters."""
        # Check if this is an enum type and we have the enum definition
        if matter_type.endswith('Enum') and enums and matter_type in enums:
            enum_obj = enums[matter_type]
            base_type = enum_obj.get_rust_enum_name()
        elif matter_type.endswith('Enum'):
            # Enum without definition - fall back to u8
            base_type = 'u8'
        elif matter_type.endswith('Bitmap'):
            if bitmaps and matter_type in bitmaps:
                bitmap_obj = bitmaps[matter_type]
                base_type = bitmap_obj.get_rust_bitmap_name()
            else:
                # Bitmap without definition - fall back to base type
                base_type = 'u8'
        else:
            # Look up Rust type from TYPE_MAP
            base_type = cls.TYPE_MAP.get(matter_type, (None, 'u8'))[1]

        # Handle list types
        if is_list or matter_type == 'list':
            return f"Vec<{base_type}>"

        return base_type
