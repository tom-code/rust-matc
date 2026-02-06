"""
Matter attribute definitions.
"""

from typing import Dict, Optional, TYPE_CHECKING

from ..naming import convert_to_snake_case, escape_rust_keyword
from ..type_mapping import MatterType
from .tlv_helpers import (
    _generate_struct_field_assignments,
    _generate_list_decoder,
    _generate_single_value_decoder,
)
from .field import MatterField

if TYPE_CHECKING:
    from .enums import MatterEnum, MatterBitmap
    from .structs import MatterStruct


class AttributeField:
    """Represents a Matter attribute.

    This class wraps a MatterField and adds attribute-specific metadata (hex_id)
    and generation methods.
    """

    def __init__(self, hex_id: str, field: MatterField):
        """
        Initialize an AttributeField.

        Args:
            hex_id: Hex string ID for the attribute (e.g., '0x0000')
            field: MatterField containing the attribute's field data
        """
        self.hex_id = hex_id
        self._field = field

    # Delegate properties to the internal MatterField
    @property
    def id(self) -> str:
        """Get the hex ID for display in generated doc comments."""
        return self.hex_id

    @property
    def name(self) -> str:
        """Get the attribute name."""
        return self._field.name

    @property
    def attr_type(self) -> str:
        """Get the attribute type (alias for field_type)."""
        return self._field.field_type

    @property
    def default(self) -> Optional[str]:
        """Get the default value."""
        return self._field.default

    @property
    def nullable(self) -> bool:
        """Check if the attribute is nullable."""
        return self._field.nullable

    @property
    def entry_type(self) -> Optional[str]:
        """Get the entry type for list attributes."""
        return self._field.entry_type

    @property
    def is_list(self) -> bool:
        """Check if this is a list attribute."""
        return self._field.is_list

    def get_rust_function_name(self) -> str:
        """Convert attribute name to snake_case Rust function name."""
        return f"decode_{escape_rust_keyword(convert_to_snake_case(self.name))}"

    def get_rust_return_type(self, structs: Optional[Dict[str, 'MatterStruct']] = None, enums: Optional[Dict[str, 'MatterEnum']] = None, bitmaps: Optional[Dict[str, 'MatterBitmap']] = None) -> str:
        """Get the Rust return type for this attribute."""
        if self.is_list:
            if self.entry_type:
                # Check if it's a custom struct
                if structs and self.entry_type in structs:
                    struct_name = structs[self.entry_type].get_rust_struct_name()
                    return f"Vec<{struct_name}>"
                else:
                    # Map entry types to Rust types
                    entry_rust_type = MatterType.get_rust_type(self.entry_type, enums=enums, bitmaps=bitmaps)
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
                rust_type = MatterType.get_rust_type(self.attr_type, enums=enums, bitmaps=bitmaps)
                if self.nullable:
                    return f"Option<{rust_type}>"
                return rust_type

    def generate_decode_function(self, structs: Optional[Dict[str, 'MatterStruct']] = None, enums: Optional[Dict[str, 'MatterEnum']] = None, bitmaps: Optional[Dict[str, 'MatterBitmap']] = None) -> str:
        """Generate Rust decode function for this attribute."""
        func_name = self.get_rust_function_name()
        return_type = self.get_rust_return_type(structs, enums, bitmaps)
        clean_id = self.id

        if self.is_list:
            if self.entry_type and structs and self.entry_type in structs:
                # Use custom struct decoder
                struct = structs[self.entry_type]
                struct_name = struct.get_rust_struct_name()

                # Generate field assignments
                field_assignments = _generate_struct_field_assignments(struct.fields, structs, enums, "item", bitmaps)
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
                decode_logic = _generate_list_decoder(self.entry_type, enums, bitmaps)
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
            tlv_type = MatterType.get_tlv_type(self.attr_type, bitmaps=bitmaps)

            # Check if this is a custom struct type
            if structs and self.attr_type in structs:
                # Handle custom struct decoding
                struct = structs[self.attr_type]
                struct_name = struct.get_rust_struct_name()

                # Generate field assignments for the struct
                field_assignments = _generate_struct_field_assignments(struct.fields, structs, enums, "item", bitmaps)
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
                decode_logic = _generate_single_value_decoder(self.attr_type, self.nullable, enums, bitmaps)

        return f'''/// Decode {self.name} attribute ({clean_id})
pub fn {func_name}(inp: &tlv::TlvItemValue) -> anyhow::Result<{return_type}> {{
{decode_logic}
}}'''
