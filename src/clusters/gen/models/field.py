"""
Unified field representation for Matter commands, structs, and attributes.
"""

from typing import Optional, Dict, TYPE_CHECKING

from ..naming import (
    convert_to_snake_case,
    escape_rust_keyword,
)

if TYPE_CHECKING:
    from .enums import MatterEnum, MatterBitmap


class MatterField:
    """
    Unified representation of a field in Matter commands, structs, and attributes.

    This class replaces the previous CommandField and tuple representations,
    providing a single consistent data structure for all field types.
    """

    def __init__(
        self,
        id: int,
        name: str,
        field_type: str,
        entry_type: Optional[str] = None,
        default: Optional[str] = None,
        nullable: bool = False,
        mandatory: bool = True
    ):
        """
        Initialize a MatterField.

        Args:
            id: TLV tag ID for this field
            name: Field name from XML specification
            field_type: Matter type ('uint8', 'list', 'FooEnum', 'BarStruct', etc.)
            entry_type: For list fields, the type of list entries
            default: Default value from XML (if any)
            nullable: Whether this field is nullable (optional in Matter)
            mandatory: Whether this field is mandatory
        """
        self.id = id
        self.name = name
        self.field_type = field_type
        self.entry_type = entry_type
        self.default = default
        self.nullable = nullable
        self.mandatory = mandatory

    @property
    def is_list(self) -> bool:
        """Check if this field is a list type."""
        return self.field_type == 'list'

    def get_rust_param_name(self) -> str:
        """Convert field name to snake_case Rust parameter name."""
        return escape_rust_keyword(convert_to_snake_case(self.name))

    def _get_default_value(self, enums: Optional[Dict[str, 'MatterEnum']] = None, bitmaps: Optional[Dict[str, 'MatterBitmap']] = None) -> str:
        """
        Generate appropriate default value based on field type and XML default attribute.

        Args:
            enums: Dictionary of enum definitions (not currently used but kept for API consistency)
            bitmaps: Dictionary of bitmap definitions (not currently used but kept for API consistency)

        Returns:
            Rust code string representing the default value
        """
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

    def __iter__(self):
        """
        Tuple compatibility: allows (id, name, type, entry_type) destructuring.

        This enables gradual migration from tuple-based code by allowing existing
        loops like `for field_id, field_name, field_type, entry_type in fields`
        to continue working without changes.
        """
        return iter((self.id, self.name, self.field_type, self.entry_type))
