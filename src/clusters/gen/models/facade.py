"""
Typed cluster façade emitter.

For each Matter cluster this module emits thin async wrapper functions that
hide the three-step encode / invoke / decode (or two-step read / decode)
choreography users currently have to perform by hand. One function per
commandToServer, one `read_*` per attribute.

Signatures mirror the existing `encode_*` / `decode_*` helpers exactly
(via `MatterCommand.render_params` and `AttributeField.get_rust_return_type`)
so façade and codec never drift.
"""

from typing import Dict, Optional, TYPE_CHECKING

from ..naming import (
    convert_to_snake_case,
    escape_rust_keyword,
    upper_ident,
)

if TYPE_CHECKING:
    from .commands import MatterCommand, MatterCommandResponse
    from .attributes import AttributeField
    from .structs import MatterStruct
    from .enums import MatterEnum, MatterBitmap


def emit_command_facade(
    cmd: 'MatterCommand',
    cluster_upper: str,
    cluster_human: str,
    structs: Dict[str, 'MatterStruct'],
    enums: Optional[Dict[str, 'MatterEnum']] = None,
    bitmaps: Optional[Dict[str, 'MatterBitmap']] = None,
    response_by_name: Optional[Dict[str, 'MatterCommandResponse']] = None,
) -> str:
    """Emit one typed facade function for a command.

    ACK-only commands return `anyhow::Result<()>` and use `invoke_request`.
    Commands with a typed response struct return `anyhow::Result<FooResponse>`
    and use `invoke_request2` + the generated decode function.
    """
    fn_name = escape_rust_keyword(convert_to_snake_case(cmd.name))
    cluster_const = f"crate::clusters::defs::CLUSTER_ID_{cluster_upper}"
    cmd_const = f"crate::clusters::defs::CLUSTER_{cluster_upper}_CMD_ID_{upper_ident(cmd.name)}"

    param_fields, use_param_struct, param_struct_name = cmd.render_params(structs, enums, bitmaps)

    # Rename any command parameter that collides with the facade's own
    # `conn` / `endpoint` binding - both are reserved in the facade signature.
    # The encoder still receives the original value; only the local binding is
    # renamed in the facade to keep Rust from shadowing (or erroring on duplicate).
    reserved = {"conn", "endpoint"}
    renamed_fields = []
    for n, t in param_fields:
        local = f"{n}_" if n in reserved else n
        renamed_fields.append((local, n, t))

    # Build the signature tail and the forwarded args for encode_*.
    if use_param_struct and param_struct_name:
        sig_tail = f", params: {param_struct_name}"
        encode_args = "params"
        payload_expr = f"&{cmd.get_rust_function_name()}({encode_args})?"
    elif renamed_fields:
        sig_tail = ", " + ", ".join(f"{local}: {t}" for local, _, t in renamed_fields)
        encode_args = ", ".join(local for local, _, _ in renamed_fields)
        payload_expr = f"&{cmd.get_rust_function_name()}({encode_args})?"
    else:
        # Zero-arg command (On, Off, Toggle, ...) - no encoder is emitted.
        sig_tail = ""
        payload_expr = "&[]"

    sig = f"conn: &crate::controller::Connection, endpoint: u16{sig_tail}"

    # Choose return type / invoke path based on presence of typed response.
    resp = None
    if cmd.response_name and response_by_name:
        resp = response_by_name.get(cmd.response_name)

    if resp and resp.fields:
        ret_ty = resp.get_rust_struct_name()
        decode_fn = f"decode_{escape_rust_keyword(convert_to_snake_case(resp.name))}"
        body = (
            f"    let tlv = conn.invoke_request2(endpoint, {cluster_const}, {cmd_const}, {payload_expr}).await?;\n"
            f"    {decode_fn}(&tlv)"
        )
    else:
        ret_ty = "()"
        body = (
            f"    conn.invoke_request(endpoint, {cluster_const}, {cmd_const}, {payload_expr}).await?;\n"
            f"    Ok(())"
        )

    return (
        f"/// Invoke `{cmd.name}` command on cluster `{cluster_human}`.\n"
        f"pub async fn {fn_name}({sig}) -> anyhow::Result<{ret_ty}> {{\n"
        f"{body}\n"
        f"}}\n\n"
    )


def emit_attribute_facade(
    attr: 'AttributeField',
    cluster_upper: str,
    cluster_human: str,
    structs: Optional[Dict[str, 'MatterStruct']] = None,
    enums: Optional[Dict[str, 'MatterEnum']] = None,
    bitmaps: Optional[Dict[str, 'MatterBitmap']] = None,
) -> str:
    """Emit one typed facade function that reads an attribute."""
    fn_name = f"read_{escape_rust_keyword(convert_to_snake_case(attr.name))}"
    cluster_const = f"crate::clusters::defs::CLUSTER_ID_{cluster_upper}"
    attr_const = f"crate::clusters::defs::CLUSTER_{cluster_upper}_ATTR_ID_{upper_ident(attr.name)}"
    ret_ty = attr.get_rust_return_type(structs, enums, bitmaps)
    decode_fn = attr.get_rust_function_name()

    return (
        f"/// Read `{attr.name}` attribute from cluster `{cluster_human}`.\n"
        f"pub async fn {fn_name}(conn: &crate::controller::Connection, endpoint: u16) "
        f"-> anyhow::Result<{ret_ty}> {{\n"
        f"    let tlv = conn.read_request2(endpoint, {cluster_const}, {attr_const}).await?;\n"
        f"    {decode_fn}(&tlv)\n"
        f"}}\n\n"
    )
