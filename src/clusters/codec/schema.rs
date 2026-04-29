// Shared types for runtime-introspectable command schemas.
// Referenced by generated per-cluster codec files and by matc consumers.

#[derive(Clone, Debug, serde::Serialize)]
pub struct CommandField {
    pub tag: u32,
    pub name: &'static str,
    pub kind: FieldKind,
    pub optional: bool,
    pub nullable: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FieldKind {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    Bool,
    String,
    OctetString,
    Enum {
        name: &'static str,
        variants: &'static [(u32, &'static str)],
    },
    Bitmap {
        name: &'static str,
        bits: &'static [(u32, &'static str)],
    },
    Struct {
        name: &'static str,
    },
    List {
        entry_type: &'static str,
    },
}
