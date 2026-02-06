"""
Matter struct definitions.
"""

import re
from typing import Dict, List, Optional, TYPE_CHECKING

from ..naming import convert_to_snake_case, escape_rust_keyword
from ..type_mapping import MatterType
from .field import MatterField

if TYPE_CHECKING:
    from .enums import MatterEnum, MatterBitmap


class MatterStruct:
    """Represents a Matter struct definition."""

    def __init__(self, name: str):
        self.name = name
        self.fields: List[MatterField] = []

    def add_field(self, field: MatterField):
        """Add a field to this struct."""
        self.fields.append(field)

    def get_rust_struct_name(self) -> str:
        """Convert struct name to PascalCase Rust struct name."""
        # Remove "Struct" suffix if present
        name = self.name.replace('Struct', '')
        # Split on capital letters and rejoin in PascalCase
        # Handle cases like "DeviceTypeStruct" -> "DeviceType"
        words = re.findall(r'[A-Z][a-z]*', name)
        return ''.join(words) if words else name

    def generate_rust_struct(self, structs: Optional[Dict[str, 'MatterStruct']] = None, enums: Optional[Dict[str, 'MatterEnum']] = None, bitmaps: Optional[Dict[str, 'MatterBitmap']] = None) -> str:
        """Generate Rust struct definition."""
        from .tlv_helpers import _generate_rust_struct_definition

        struct_name = self.get_rust_struct_name()
        return _generate_rust_struct_definition(struct_name, self.fields, structs, enums, bitmaps)

    def generate_decode_function(self, is_list: bool = False, structs: Optional[Dict[str, 'MatterStruct']] = None, enums: Optional[Dict[str, 'MatterEnum']] = None, bitmaps: Optional[Dict[str, 'MatterBitmap']] = None) -> str:
        """Generate decode function for this struct."""
        from .tlv_helpers import _generate_struct_field_assignments

        struct_name = self.get_rust_struct_name()
        func_name = f"decode_{convert_to_snake_case(self.name)}"

        if is_list:
            func_name += "_list"
            return_type = f"Vec<{struct_name}>"
        else:
            return_type = struct_name

        # Use shared helper to generate field assignments
        if structs is None:
            structs = {}
        if enums is None:
            enums = {}

        field_assignments = _generate_struct_field_assignments(
            self.fields, structs, enums, "item", bitmaps
        )
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
