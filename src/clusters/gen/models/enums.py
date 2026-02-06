"""
Matter enum and bitmap definitions.
"""

import re
from typing import List, Tuple


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


def generate_bitmap_macro() -> str:
    """Generate the macro that implements common bitmap methods.

    NOTE: This function is deprecated but kept for backwards compatibility.
    The new approach uses crate::clusters::bitmap::Bitmap<Tag, Base> which provides
    all the same methods without needing a per-file macro.
    """
    return ''  # No longer needed - using shared bitmap type


class MatterBitmap:
    """Represents a Matter bitmap definition."""

    def __init__(self, name: str):
        self.name = name
        self.bitfields: List[Tuple[int, str, str]] = []  # (bit_position, name, summary)
        self._force_bitmap_suffix = False  # Set to True to keep "Bitmap" suffix

    def add_bitfield(self, bit_pos: int, field_name: str, summary: str = ""):
        """Add a bitfield to this bitmap."""
        # Sanitize the bitfield name to be a valid Rust constant identifier
        sanitized_name = self._sanitize_bitfield_name(field_name)
        self.bitfields.append((bit_pos, sanitized_name, summary))

    def _sanitize_bitfield_name(self, name: str) -> str:
        """Sanitize bitfield name to be a valid Rust constant identifier (SCREAMING_SNAKE_CASE)."""
        # Replace spaces with underscores
        name = name.replace(' ', '_')

        # Replace any other invalid characters (e.g., hyphens, special chars)
        name = re.sub(r'[^a-zA-Z0-9_]', '_', name)

        # Convert to SCREAMING_SNAKE_CASE
        # Handle camelCase and PascalCase by inserting underscores before capitals
        name = re.sub(r'([a-z])([A-Z])', r'\1_\2', name)
        name = name.upper()

        # Remove consecutive underscores
        name = re.sub(r'_+', '_', name)

        # If it starts with a digit, prefix with "BIT_"
        if name and name[0].isdigit():
            name = f"BIT_{name}"

        return name if name else "UNKNOWN"

    def get_rust_bitmap_name(self) -> str:
        """Convert bitmap name to PascalCase Rust type name."""
        # Keep "Bitmap" suffix if forced (to avoid name collisions)
        if self._force_bitmap_suffix:
            name = self.name
        else:
            # Remove "Bitmap" suffix if present for cleaner naming
            name = self.name.replace('Bitmap', '')
        # Split on capital letters and rejoin in PascalCase
        words = re.findall(r'[A-Z][a-z]*', name)
        return ''.join(words) if words else name

    def get_base_type(self) -> str:
        """Determine the base type (u8/u16/u32/u64) based on maximum bit position."""
        if not self.bitfields:
            return "u8"  # Default to u8 for empty bitmaps

        max_bit = max(bit_pos for bit_pos, _, _ in self.bitfields)

        if max_bit < 8:
            return "u8"
        elif max_bit < 16:
            return "u16"
        elif max_bit < 32:
            return "u32"
        else:
            return "u64"

    def generate_rust_bitmap(self) -> str:
        """Generate Rust bitmap type definition as a simple type alias.

        This generates:
        1. A type alias to the base integer type (e.g., type OnOffControl = u8)
        2. A module with the bitfield constants (e.g., mod on_off_control)
        """
        bitmap_name = self.get_rust_bitmap_name()
        base_type = self.get_base_type()

        # Generate bitfield constants
        constants = []
        for bit_pos, field_name, summary in self.bitfields:
            bit_value = 1 << bit_pos
            if summary:
                constants.append(f"    /// {summary}")
            constants.append(f"    pub const {field_name}: {base_type} = 0x{bit_value:02X};")

        # Generate simple type alias
        result = f'''/// {bitmap_name} bitmap type
pub type {bitmap_name} = {base_type};'''

        # Add module with constants if any
        if constants:
            module_name = bitmap_name.lower().replace('bitmap', '').strip('_')
            if not module_name:
                module_name = bitmap_name.lower()
            constants_str = "\n".join(constants)
            result += f'''

/// Constants for {bitmap_name}
pub mod {module_name} {{
{constants_str}
}}'''

        return result
