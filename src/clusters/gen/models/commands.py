"""
Matter command definitions.
"""

import re
from typing import Dict, List, Optional, TYPE_CHECKING

from ..naming import (
    convert_to_snake_case,
    convert_to_pascal_case,
    escape_rust_keyword,
)
from ..type_mapping import MatterType
from .tlv_helpers import (
    _generate_struct_field_assignments,
    generate_field_tlv_encoding,
)
from .field import MatterField

if TYPE_CHECKING:
    from .enums import MatterEnum, MatterBitmap
    from .structs import MatterStruct


class MatterCommand:
    """Represents a Matter command with its fields."""

    def __init__(self, id: str, name: str, direction: str):
        self.id = id
        self.name = name
        self.direction = direction
        self.fields: List[MatterField] = []

    def add_field(self, field: MatterField):
        """Add a field to this command."""
        self.fields.append(field)

    def get_rust_function_name(self) -> str:
        """Convert command name to snake_case Rust function name."""
        return f"encode_{escape_rust_keyword(convert_to_snake_case(self.name))}"

    def get_rust_params_struct_name(self) -> str:
        """Get the name for the parameters struct."""
        # Convert command name to PascalCase and append Params
        return f"{convert_to_pascal_case(self.name)}Params"

    def generate_rust_function(self, structs: Dict[str, 'MatterStruct'], enums: Optional[Dict[str, 'MatterEnum']] = None, bitmaps: Optional[Dict[str, 'MatterBitmap']] = None) -> str:
        """Generate complete Rust function for encoding this command."""
        func_name = self.get_rust_function_name()

        # Generate function parameters - store both for signature and struct generation
        params = []  # List of "name: type" strings
        param_fields = []  # List of (name, type) tuples
        for field in self.fields:
            param_name = field.get_rust_param_name()
            # If this is a list of a custom struct, expose Vec<StructName>
            if field.is_list and field.entry_type and structs and field.entry_type in structs:
                item_struct = structs[field.entry_type]
                rust_type = f"Vec<{item_struct.get_rust_struct_name()}>"
            elif field.is_list and field.entry_type and field.entry_type.endswith('Struct') and (not structs or field.entry_type not in structs):
                # Skip list fields that reference undefined structs from other clusters
                continue
            elif not field.is_list and field.field_type.endswith('Struct') and structs and field.field_type in structs:
                # Single struct field
                struct_def = structs[field.field_type]
                rust_type = struct_def.get_rust_struct_name()
            elif not field.is_list and field.field_type.endswith('Struct') and (not structs or field.field_type not in structs):
                # Skip fields that reference undefined structs from other clusters
                continue
            elif not field.is_list and field.field_type.endswith('Enum'):
                # Check if we have the enum definition
                if enums and field.field_type in enums:
                    rust_type = enums[field.field_type].get_rust_enum_name()
                else:
                    # Fallback to u8 if enum not defined
                    rust_type = 'u8'
            elif not field.is_list and field.field_type.endswith('Bitmap'):
                # Check if we have the bitmap definition
                if bitmaps and field.field_type in bitmaps:
                    rust_type = bitmaps[field.field_type].get_rust_bitmap_name()
                else:
                    # Fallback to u8 if bitmap not defined
                    rust_type = 'u8'
            else:
                # Use MatterType mapping (handles primitive lists when is_list=True)
                rust_type = MatterType.get_rust_type(field.entry_type if field.is_list and field.entry_type else field.field_type, field.is_list, enums=enums, bitmaps=bitmaps)

            if field.nullable:
                rust_type = f"Option<{rust_type}>"

            params.append(f"{param_name}: {rust_type}")
            param_fields.append((param_name, rust_type))

        # Determine if we need a parameter struct (more than 7 params)
        use_param_struct = len(params) > 7
        struct_name = self.get_rust_params_struct_name() if use_param_struct else None

        # Generate function signature
        if use_param_struct:
            param_str = f"params: {struct_name}"
            # Prefix for accessing parameters (e.g., "params.field_name")
            param_prefix = "params."
        else:
            param_str = ", ".join(params) if params else ""
            param_prefix = ""

        # Generate TLV encoding - collect both pre-statements and field encodings
        pre_statements = []  # Statements that need to go before vec![]
        tlv_fields = []  # Field encodings that go inside vec![]

        for field in self.fields:
            # Skip fields with undefined cross-cluster struct types (consistent with param generation)
            if not field.is_list and field.field_type.endswith('Struct') and (not structs or field.field_type not in structs):
                continue

            param_name = field.get_rust_param_name()
            # Prepend prefix if using parameter struct
            full_param_name = f"{param_prefix}{param_name}"
            encoding_result = generate_field_tlv_encoding(field, full_param_name, structs, enums, bitmaps)

            # Skip empty encoding results (from cross-cluster struct skipping)
            if not encoding_result:
                continue

            # Check if this is a multi-line struct encoding that needs pre-statements
            if '\n' in encoding_result and field.field_type.endswith('Struct'):
                # Split into pre-statements and the final field line
                lines = encoding_result.split('\n')
                # First line is comment, middle lines are statements, last line is the field push
                pre_statements.extend(lines[:-1])  # Everything except last line
                tlv_fields.append(lines[-1])  # Last line
            else:
                tlv_fields.append(encoding_result)

        # Generate pre-statement block (if any)
        pre_stmt_str = "\n    ".join(pre_statements) if pre_statements else ""
        tlv_fields_str = "\n".join(tlv_fields) if tlv_fields else "        // No fields"

        # Clean up command ID format
        clean_id = self.id

        # Generate parameter struct if needed
        struct_def = ""
        if use_param_struct:
            struct_fields_str = "\n".join([f"    pub {name}: {typ}," for name, typ in param_fields])
            struct_def = f'''/// Parameters for {self.name} command
pub struct {struct_name} {{
{struct_fields_str}
}}

'''

        # Generate function
        if pre_statements:
            function = f'''{struct_def}/// Encode {self.name} command ({clean_id})
pub fn {func_name}({param_str}) -> anyhow::Result<Vec<u8>> {{
    {pre_stmt_str}
    let tlv = tlv::TlvItemEnc {{
        tag: 0,
        value: tlv::TlvItemValueEnc::StructInvisible(vec![
{tlv_fields_str}
        ]),
    }};
    Ok(tlv.encode()?)
}}'''
        else:
            function = f'''{struct_def}/// Encode {self.name} command ({clean_id})
pub fn {func_name}({param_str}) -> anyhow::Result<Vec<u8>> {{
    let tlv = tlv::TlvItemEnc {{
        tag: 0,
        value: tlv::TlvItemValueEnc::StructInvisible(vec![
{tlv_fields_str}
        ]),
    }};
    Ok(tlv.encode()?)
}}'''
        return function


class MatterCommandResponse:
    """Represents a Matter command response (responseFromServer)."""

    def __init__(self, id: str, name: str):
        self.id = id
        self.name = name
        self.fields: List[MatterField] = []

    def add_field(self, field: MatterField):
        """Add a field to this command response."""
        self.fields.append(field)

    def get_rust_struct_name(self) -> str:
        """Convert response name to PascalCase Rust struct name, keeping 'Response' suffix."""
        # Keep the full name including "Response" suffix
        words = re.findall(r'[A-Z][a-z]*', self.name)
        return ''.join(words) if words else self.name

    def generate_rust_struct(self, structs: Optional[Dict[str, 'MatterStruct']] = None, enums: Optional[Dict[str, 'MatterEnum']] = None, bitmaps: Optional[Dict[str, 'MatterBitmap']] = None) -> str:
        """Generate Rust struct definition for response command."""
        from .tlv_helpers import _generate_rust_struct_definition

        struct_name = self.get_rust_struct_name()
        return _generate_rust_struct_definition(struct_name, self.fields, structs, enums, bitmaps)

    def generate_decode_function(self, structs: Optional[Dict[str, 'MatterStruct']] = None, enums: Optional[Dict[str, 'MatterEnum']] = None, bitmaps: Optional[Dict[str, 'MatterBitmap']] = None) -> str:
        """Generate decode function for this response command."""
        struct_name = self.get_rust_struct_name()
        func_name = f"decode_{escape_rust_keyword(convert_to_snake_case(self.name))}"

        # Clean up command ID (remove 0x prefix if present)
        clean_id = self.id.replace('0x', '') if self.id.startswith('0x') else self.id

        # Generate field assignments using the shared helper
        field_assignments_str = "\n".join(_generate_struct_field_assignments(self.fields, structs, enums, "item", bitmaps))

        return f'''/// Decode {self.name} command response ({clean_id})
pub fn {func_name}(inp: &tlv::TlvItemValue) -> anyhow::Result<{struct_name}> {{
    if let tlv::TlvItemValue::List(_fields) = inp {{
        let item = tlv::TlvItem {{ tag: 0, value: inp.clone() }};
        Ok({struct_name} {{
{field_assignments_str}
        }})
    }} else {{
        Err(anyhow::anyhow!("Expected struct fields"))
    }}
}}'''
