"""
XML parsing for Matter cluster specifications.

This module contains the ClusterParser class that extracts information from
Matter cluster XML files.
"""

import xml.etree.ElementTree as ET
from typing import Dict, List

from .naming import convert_to_snake_case, escape_rust_keyword
from .models import (
    MatterEnum,
    MatterBitmap,
    MatterStruct,
    AttributeField,
    MatterCommand,
    MatterCommandResponse,
    MatterField,
    MatterEvent,
)


def _parse_field_element(field_elem) -> MatterField:
    """Parse a field XML element and return a MatterField object.

    Returns: MatterField with all field attributes populated
    """
    field_id = int(field_elem.get('id', '0'))
    field_name = field_elem.get('name', 'Unknown')
    field_type = field_elem.get('type', 'uint8')
    field_default = field_elem.get('default')

    # Check for entry type (for list fields)
    entry_elem = field_elem.find('entry')
    entry_type = entry_elem.get('type') if entry_elem is not None else None

    # Check if field is nullable
    quality_elem = field_elem.find('quality')
    nullable = quality_elem.get('nullable', 'false').lower() == 'true' if quality_elem is not None else False

    # Check if field is mandatory
    mandatory_elem = field_elem.find('mandatoryConform')
    mandatory = mandatory_elem is not None

    return MatterField(
        id=field_id,
        name=field_name,
        field_type=field_type,
        entry_type=entry_type,
        default=field_default,
        nullable=nullable,
        mandatory=mandatory
    )


class ClusterParser:
    """Parses Matter cluster XML files."""

    def __init__(self, xml_file: str):
        self.xml_file = xml_file
        self.tree = ET.parse(xml_file)
        self.root = self.tree.getroot()
        self.cluster_name = self.root.get('name', 'Unknown')
        self.cluster_id = self.root.get('id', '0x0000')

    def parse_commands(self) -> List[MatterCommand]:
        """Parse all commands from the XML."""
        commands = []

        commands_elem = self.root.find('commands')
        if commands_elem is None:
            return commands

        for cmd_elem in commands_elem.findall('command'):
            cmd_id = cmd_elem.get('id', '0x00')
            cmd_name = cmd_elem.get('name', 'Unknown')
            cmd_direction = cmd_elem.get('direction', 'commandToServer')

            # Only process commands to server (client-to-server)
            if cmd_direction != 'commandToServer':
                continue

            command = MatterCommand(cmd_id, cmd_name, cmd_direction)

            # Parse command fields
            for field_elem in cmd_elem.findall('field'):
                field = _parse_field_element(field_elem)
                command.add_field(field)

            # Handle commands with similar structure (like *WithOnOff commands)
            # If a command has no fields but is similar to another, inherit fields
            if not command.fields and cmd_name.endswith('WithOnOff'):
                base_name = cmd_name.replace('WithOnOff', '')
                # Look for the base command to inherit fields
                for base_cmd_elem in commands_elem.findall('command'):
                    if base_cmd_elem.get('name') == base_name:
                        # Copy fields from base command
                        for field_elem in base_cmd_elem.findall('field'):
                            field = _parse_field_element(field_elem)
                            command.add_field(field)
                        break

            commands.append(command)

        return commands

    def parse_response_commands(self) -> List[MatterCommandResponse]:
        """Parse all response commands from the XML."""
        responses = []

        commands_elem = self.root.find('commands')
        if commands_elem is None:
            return responses

        for cmd_elem in commands_elem.findall('command'):
            cmd_direction = cmd_elem.get('direction', 'commandToServer')

            # Only process response commands (server-to-client)
            if cmd_direction != 'responseFromServer':
                continue

            cmd_id = cmd_elem.get('id', '0x00')
            cmd_name = cmd_elem.get('name', 'Unknown')

            response = MatterCommandResponse(cmd_id, cmd_name)

            # Parse response fields
            for field_elem in cmd_elem.findall('field'):
                field = _parse_field_element(field_elem)
                response.add_field(field)

            responses.append(response)

        return responses

    def parse_events(self) -> List[MatterEvent]:
        """Parse all events from the XML."""
        events = []

        events_elem = self.root.find('events')
        if events_elem is None:
            return events

        for event_elem in events_elem.findall('event'):
            event_id = event_elem.get('id', '0x00')
            event_name = event_elem.get('name', 'Unknown')
            event_priority = event_elem.get('priority', 'info')

            event = MatterEvent(event_id, event_name, event_priority)

            # Parse event fields
            for field_elem in event_elem.findall('field'):
                field = _parse_field_element(field_elem)
                event.add_field(field)

            events.append(event)

        return events

    def parse_attributes(self) -> List[AttributeField]:
        """Parse all attributes from the XML."""
        attributes = []

        attributes_elem = self.root.find('attributes')
        if attributes_elem is None:
            return attributes

        for attr_elem in attributes_elem.findall('attribute'):
            attr_id = attr_elem.get('id', '0x0000')

            # Parse field using the shared helper, but attr_elem is not a field element
            # We need to manually construct field data for attributes
            attr_name = attr_elem.get('name', 'Unknown')
            attr_type = attr_elem.get('type', 'uint8')
            attr_default = attr_elem.get('default')

            # Check for entry type (for list attributes)
            entry_elem = attr_elem.find('entry')
            entry_type = None
            if entry_elem is not None:
                entry_type = entry_elem.get('type')

            # Check if attribute is nullable
            quality_elem = attr_elem.find('quality')
            nullable = False
            if quality_elem is not None:
                nullable = quality_elem.get('nullable', 'false').lower() == 'true'

            # Create MatterField for the attribute data
            field = MatterField(
                id=0,  # Attributes don't use TLV tag IDs in the same way
                name=attr_name,
                field_type=attr_type,
                entry_type=entry_type,
                default=attr_default,
                nullable=nullable,
                mandatory=True  # Default for attributes
            )

            attribute = AttributeField(attr_id, field)
            attributes.append(attribute)

        return attributes

    def parse_structs(self) -> Dict[str, MatterStruct]:
        """Parse all struct definitions from the XML."""
        structs = {}

        data_types_elem = self.root.find('dataTypes')
        if data_types_elem is None:
            return structs

        for struct_elem in data_types_elem.findall('struct'):
            struct_name = struct_elem.get('name', 'Unknown')
            struct = MatterStruct(struct_name)

            # Parse struct fields
            for field_elem in struct_elem.findall('field'):
                field = _parse_field_element(field_elem)
                struct.add_field(field)

            structs[struct_name] = struct

        return structs

    def parse_enums(self) -> Dict[str, MatterEnum]:
        """Parse all enum definitions from the XML."""
        enums = {}

        data_types_elem = self.root.find('dataTypes')
        if data_types_elem is None:
            return enums

        for enum_elem in data_types_elem.findall('enum'):
            enum_name = enum_elem.get('name', 'Unknown')
            enum = MatterEnum(enum_name)

            # Parse enum items
            for item_elem in enum_elem.findall('item'):
                value_str = item_elem.get('value', '0')
                item_name = item_elem.get('name', 'Unknown')
                summary = item_elem.get('summary', '')

                # Parse the value (can be decimal or hex)
                try:
                    if value_str.startswith('0x') or value_str.startswith('0X'):
                        value = int(value_str, 16)
                    else:
                        value = int(value_str)
                except ValueError:
                    value = 0

                enum.add_item(value, item_name, summary)

            enums[enum_name] = enum

        return enums

    def parse_bitmaps(self) -> Dict[str, MatterBitmap]:
        """Parse all bitmap definitions from the XML."""
        bitmaps = {}

        data_types_elem = self.root.find('dataTypes')
        if data_types_elem is None:
            return bitmaps

        for bitmap_elem in data_types_elem.findall('bitmap'):
            bitmap_name = bitmap_elem.get('name', 'Unknown')
            bitmap = MatterBitmap(bitmap_name)

            # Parse bitfield items
            for bitfield_elem in bitmap_elem.findall('bitfield'):
                # Get bit position (ignore bit ranges with from/to for now)
                bit_str = bitfield_elem.get('bit')
                if bit_str is None:
                    # Skip bit ranges (from/to attributes) for initial implementation
                    continue

                field_name = bitfield_elem.get('name', 'Unknown')
                summary = bitfield_elem.get('summary', '')

                # Parse the bit position (can be decimal or hex)
                try:
                    if bit_str.startswith('0x') or bit_str.startswith('0X'):
                        bit_pos = int(bit_str, 16)
                    else:
                        bit_pos = int(bit_str)
                except (ValueError, AttributeError):
                    # Skip invalid bit positions
                    continue

                bitmap.add_bitfield(bit_pos, field_name, summary)

            bitmaps[bitmap_name] = bitmap

        return bitmaps
