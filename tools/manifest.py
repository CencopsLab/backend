import struct
import sys
import zipfile
from pathlib import Path

START_TAG = 0x0102
END_TAG = 0x0103
TEXT = 0x0104


def u16(data, pos):
    return struct.unpack_from("<H", data, pos)[0]


def u32(data, pos):
    return struct.unpack_from("<I", data, pos)[0]


def read_utf8_string(data, pos):
    length = data[pos]
    pos += 1
    if length & 0x80:
        length = ((length & 0x7F) << 8) | data[pos]
        pos += 1
    raw = data[pos:pos + length]
    pos += length + 1
    return raw.decode("utf-8", errors="replace"), pos


def read_utf16_string(data, pos):
    length = u16(data, pos)
    pos += 2
    if length & 0x8000:
        length = ((length & 0x7FFF) << 16) | u16(data, pos)
        pos += 2
    raw = data[pos:pos + length * 2]
    pos += length * 2 + 2
    return raw.decode("utf-16le", errors="replace"), pos


def parse_string_pool(data, chunk_start):
    string_count = u32(data, chunk_start + 8)
    flags = u32(data, chunk_start + 16)
    strings_start = u32(data, chunk_start + 20)
    offsets_start = chunk_start + 28
    offsets = [u32(data, offsets_start + index * 4) for index in range(string_count)]
    strings = []
    for offset in offsets:
        position = chunk_start + strings_start + offset
        value, _ = read_utf8_string(data, position) if flags & 0x100 else read_utf16_string(data, position)
        strings.append(value)
    return strings


def get_string(strings, index):
    if index == 0xFFFFFFFF:
        return None
    return strings[index] if index < len(strings) else f"<string:{index}>"


def typed_value(data, pos, strings):
    value_type = data[pos + 3]
    value_data = u32(data, pos + 4)
    if value_type == 0x00:
        return None
    if value_type == 0x01:
        return f"@0x{value_data:08x}"
    if value_type == 0x02:
        return f"?0x{value_data:08x}"
    if value_type == 0x03:
        return get_string(strings, value_data)
    if value_type == 0x10:
        return str(value_data)
    if value_type == 0x11:
        return f"0x{value_data:08x}"
    if value_type == 0x12:
        return "true" if value_data else "false"
    return f"0x{value_data:08x}"


def decode_axml(data):
    if len(data) < 8:
        raise ValueError("Invalid AndroidManifest.xml")

    strings = []
    position = 8
    output = []
    indent = 0

    while position + 8 <= len(data):
        chunk_type = u16(data, position)
        chunk_size = u32(data, position + 4)
        if chunk_size < 8 or position + chunk_size > len(data):
            break

        if chunk_type == 0x0001:
            strings = parse_string_pool(data, position)
        elif chunk_type == START_TAG:
            name = u32(data, position + 20)
            attribute_count = u32(data, position + 28)
            tag_name = get_string(strings, name)
            output.append("    " * indent + f"<{tag_name}")
            attribute_position = position + 36
            for _ in range(attribute_count):
                attribute_name = get_string(strings, u32(data, attribute_position + 4))
                raw_value = u32(data, attribute_position + 8)
                value = get_string(strings, raw_value) if raw_value != 0xFFFFFFFF else typed_value(data, attribute_position + 8, strings)
                output.append("    " * (indent + 1) + f'{attribute_name}="{value}"')
                attribute_position += 20
            output.append("    " * indent + ">")
            indent += 1
        elif chunk_type == END_TAG:
            indent = max(0, indent - 1)
            tag_name = get_string(strings, u32(data, position + 20))
            output.append("    " * indent + f"</{tag_name}>")
        elif chunk_type == TEXT:
            text = get_string(strings, u32(data, position + 20))
            if text:
                output.append("    " * indent + text)

        position += chunk_size

    return "\n".join(output)


def main():
    if len(sys.argv) != 2:
        print("Usage: python manifest.py application.apk", file=sys.stderr)
        sys.exit(1)

    apk_path = Path(sys.argv[1])
    if not apk_path.exists():
        print(f"APK not found: {apk_path}", file=sys.stderr)
        sys.exit(1)

    try:
        with zipfile.ZipFile(apk_path, "r") as apk:
            manifest = apk.read("AndroidManifest.xml")
    except (zipfile.BadZipFile, KeyError) as error:
        print(f"Could not read AndroidManifest.xml: {error}", file=sys.stderr)
        sys.exit(1)

    decoded = decode_axml(manifest)
    output_file = apk_path.with_name("AndroidManifest_decoded.xml")
    output_file.write_text(decoded, encoding="utf-8")
    print(output_file)


if __name__ == "__main__":
    main()
