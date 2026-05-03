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
    generate_optional_field_push,
)
from .field import MatterField

if TYPE_CHECKING:
    from .enums import MatterEnum, MatterBitmap
    from .structs import MatterStruct


def _element_to_push(element_str: str) -> str:
    """Convert a vec![] TLV element string to a tlv_fields.push() statement."""
    stripped = element_str.strip().rstrip(',')
    return f"tlv_fields.push({stripped});"


class MatterCommand:
    """Represents a Matter command with its fields."""

    def __init__(self, id: str, name: str, direction: str, response_name: Optional[str] = None):
        self.id = id
        self.name = name
        self.direction = direction
        self.response_name = response_name
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

    def render_params(self, structs: Dict[str, 'MatterStruct'], enums: Optional[Dict[str, 'MatterEnum']] = None, bitmaps: Optional[Dict[str, 'MatterBitmap']] = None):
        """Compute the parameter list for this command's encoder signature.

        Shared by `generate_rust_function` (emits the encoder) and the typed
        façade emitter (emits the wrapper that calls the encoder) so the two
        signatures never drift.

        Returns (param_fields, use_param_struct, param_struct_name):
        - param_fields: ordered list of (rust_name, rust_type) tuples
        - use_param_struct: True when >7 params and the encoder takes a single
          `params: FooParams` struct instead of positional args
        - param_struct_name: the struct name when use_param_struct, else None
        """
        param_fields = []
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

            # Wrap in Option when nullable or optional. For optional struct/list fields,
            # the encoder will use shadowed `if let Some(name) = name` to reuse the
            # existing struct/list encoder unchanged.
            if field.nullable or not field.mandatory:
                rust_type = f"Option<{rust_type}>"

            param_fields.append((param_name, rust_type))

        use_param_struct = len(param_fields) > 7
        param_struct_name = self.get_rust_params_struct_name() if use_param_struct else None
        return param_fields, use_param_struct, param_struct_name

    def generate_rust_function(self, structs: Dict[str, 'MatterStruct'], enums: Optional[Dict[str, 'MatterEnum']] = None, bitmaps: Optional[Dict[str, 'MatterBitmap']] = None) -> str:
        """Generate complete Rust function for encoding this command."""
        func_name = self.get_rust_function_name()

        param_fields, use_param_struct, struct_name = self.render_params(structs, enums, bitmaps)
        params = [f"{name}: {typ}" for name, typ in param_fields]

        # Generate function signature
        if use_param_struct:
            param_str = f"params: {struct_name}"
            # Prefix for accessing parameters (e.g., "params.field_name")
            param_prefix = "params."
        else:
            param_str = ", ".join(params) if params else ""
            param_prefix = ""

        # If any field is truly optional (not mandatory, not nullable) we must use
        # a Vec accumulator body so those fields can be omitted from TLV when absent.
        # Skip cross-cluster struct/list-of-struct fields (they would be `continue`d below).
        def _is_supported_optional(f):
            if f.mandatory or f.nullable:
                return False
            if f.field_type.endswith('Struct') and (not structs or f.field_type not in structs):
                return False
            if f.is_list and f.entry_type and f.entry_type.endswith('Struct') and (not structs or f.entry_type not in structs):
                return False
            return True
        has_truly_optional = any(_is_supported_optional(f) for f in self.fields)

        # Generate TLV encoding - collect both pre-statements and field encodings
        pre_statements = []  # Statements that need to go before the body
        tlv_fields = []      # Elements for vec![] (used only when not has_truly_optional)
        push_statements = [] # Push statements for Vec accumulator (used when has_truly_optional)

        for field in self.fields:
            # Skip fields with undefined cross-cluster struct types (consistent with param generation)
            if not field.is_list and field.field_type.endswith('Struct') and (not structs or field.field_type not in structs):
                continue

            param_name = field.get_rust_param_name()
            # Prepend prefix if using parameter struct
            full_param_name = f"{param_prefix}{param_name}"

            if has_truly_optional:
                if not field.mandatory and not field.nullable:
                    # Truly optional (any type): emit only when Some
                    push_stmt = generate_optional_field_push(field, full_param_name, structs, enums, bitmaps)
                    if push_stmt:
                        push_statements.append(push_stmt)
                else:
                    # Mandatory or nullable: encode normally, convert element to push call
                    encoding_result = generate_field_tlv_encoding(field, full_param_name, structs, enums, bitmaps)
                    if not encoding_result:
                        continue
                    # Only split struct-field multi-line results (same guard as the vec![] path).
                    # List fields also produce multi-line strings but are a single expression.
                    if '\n' in encoding_result and field.field_type.endswith('Struct'):
                        lines = encoding_result.split('\n')
                        pre_statements.extend(lines[:-1])
                        push_statements.append(_element_to_push(lines[-1]))
                    else:
                        push_statements.append(_element_to_push(encoding_result))
            else:
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
        if has_truly_optional:
            pre_stmt_str = "\n    ".join(pre_statements) if pre_statements else ""
            pre_block = f"\n    {pre_stmt_str}" if pre_statements else ""
            push_stmts_str = "\n    ".join(push_statements) if push_statements else "// No fields"
            function = f'''{struct_def}/// Encode {self.name} command ({clean_id})
pub fn {func_name}({param_str}) -> anyhow::Result<Vec<u8>> {{{pre_block}
    let mut tlv_fields: Vec<tlv::TlvItemEnc> = Vec::new();
    {push_stmts_str}
    let tlv = tlv::TlvItemEnc {{
        tag: 0,
        value: tlv::TlvItemValueEnc::StructInvisible(tlv_fields),
    }};
    Ok(tlv.encode()?)
}}'''
        elif pre_statements:
            pre_stmt_str = "\n    ".join(pre_statements)
            tlv_fields_str = "\n".join(tlv_fields) if tlv_fields else "        // No fields"
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
            tlv_fields_str = "\n".join(tlv_fields) if tlv_fields else "        // No fields"
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
