"""Matter Event Data Model and Code Generation"""

from typing import List
from .field import MatterField
from .tlv_helpers import (
    _generate_rust_struct_definition,
    _generate_struct_field_assignments
)
from ..naming import convert_to_pascal_case, convert_to_snake_case


class MatterEvent:
    """Represents a Matter event with priority and fields"""

    def __init__(self, id: str, name: str, priority: str):
        self.id = id
        self.name = name
        self.priority = priority
        self.fields: List[MatterField] = []

    def add_field(self, field: MatterField):
        """Add a field to this event"""
        self.fields.append(field)

    def get_rust_struct_name(self) -> str:
        """Get the Rust struct name for this event (PascalCase + 'Event' suffix)"""
        return f"{convert_to_pascal_case(self.name)}Event"

    def generate_rust_struct(self, structs, enums, bitmaps) -> str:
        """Generate Rust struct definition for the event"""
        if not self.fields:
            return ""

        struct_name = self.get_rust_struct_name()
        # Convert fields to tuple format expected by the helper
        struct_fields = [(f.id, f.name, f.field_type, f.entry_type) for f in self.fields]
        return _generate_rust_struct_definition(
            struct_name=struct_name,
            struct_fields=struct_fields,
            structs=structs,
            enums=enums,
            bitmaps=bitmaps
        )

    def generate_decode_function(self, structs, enums, bitmaps) -> str:
        """Generate decode function for the event"""
        if not self.fields:
            return ""

        struct_name = self.get_rust_struct_name()
        func_name = f"decode_{convert_to_snake_case(self.name)}_event"

        # Convert fields to tuple format expected by the helper
        struct_fields = [(f.id, f.name, f.field_type, f.entry_type) for f in self.fields]

        # Generate field assignments using helper
        field_assignments = _generate_struct_field_assignments(
            struct_fields=struct_fields,
            structs=structs,
            enums=enums,
            item_var='item',
            bitmaps=bitmaps
        )

        # Build function
        lines = []
        lines.append(f"/// Decode {self.name} event ({self.id}, priority: {self.priority})")
        lines.append(f"pub fn {func_name}(inp: &tlv::TlvItemValue) -> anyhow::Result<{struct_name}> {{")
        lines.append("    if let tlv::TlvItemValue::List(_fields) = inp {")
        lines.append("        let item = tlv::TlvItem { tag: 0, value: inp.clone() };")
        lines.append(f"        Ok({struct_name} {{")

        for assignment in field_assignments:
            lines.append(f"                {assignment}")

        lines.append("        })")
        lines.append("    } else {")
        lines.append('        Err(anyhow::anyhow!("Expected struct fields"))')
        lines.append("    }")
        lines.append("}")

        return "\n".join(lines)
