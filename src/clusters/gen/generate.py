#!/usr/bin/env python3
"""
Python script to generate Rust code for Matter TLV command encoding.

This script parses all Matter cluster XML files in a directory and generates Rust code
to encode TLV structures for commands using the TlvItemEnc API.

Usage:
    python generate.py <xml_directory> <output_directory>

Note: This is now a thin wrapper around the orchestrate module.
The actual code generation logic has been refactored into a modular package structure:
- naming.py: Name/type conversion utilities
- type_mapping.py: Matter type to Rust type mapping
- models/: Data model classes (enums, structs, attributes, commands)
- xml_parser.py: XML parsing logic
- orchestrate.py: Code generation orchestration and file I/O
"""

from .orchestrate import main

if __name__ == "__main__":
    main()
