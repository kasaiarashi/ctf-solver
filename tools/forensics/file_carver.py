"""
File Carver

Tools for extracting embedded files from data.
"""

import subprocess
from typing import List, Dict, Optional, Tuple
from pathlib import Path


# Common file magic bytes
MAGIC_BYTES = {
    'PNG': {
        'header': b'\x89PNG\r\n\x1a\n',
        'footer': b'\x49\x45\x4e\x44\xae\x42\x60\x82',
        'extension': '.png',
    },
    'JPEG': {
        'header': b'\xff\xd8\xff',
        'footer': b'\xff\xd9',
        'extension': '.jpg',
    },
    'GIF': {
        'header': b'GIF89a',
        'footer': b'\x00\x3b',
        'extension': '.gif',
    },
    'PDF': {
        'header': b'%PDF',
        'footer': b'%%EOF',
        'extension': '.pdf',
    },
    'ZIP': {
        'header': b'PK\x03\x04',
        'footer': b'PK\x05\x06',
        'extension': '.zip',
    },
    'RAR': {
        'header': b'Rar!\x1a\x07',
        'footer': None,
        'extension': '.rar',
    },
    'GZIP': {
        'header': b'\x1f\x8b',
        'footer': None,
        'extension': '.gz',
    },
    'BZ2': {
        'header': b'BZh',
        'footer': None,
        'extension': '.bz2',
    },
    'ELF': {
        'header': b'\x7fELF',
        'footer': None,
        'extension': '.elf',
    },
    'PE': {
        'header': b'MZ',
        'footer': None,
        'extension': '.exe',
    },
    '7Z': {
        'header': b"7z\xbc\xaf'\x1c",
        'footer': None,
        'extension': '.7z',
    },
    'TAR': {
        'header': b'ustar',
        'footer': None,
        'extension': '.tar',
    },
}


def get_file_type(data: bytes) -> Optional[str]:
    """
    Identify file type from magic bytes.

    Args:
        data: File content or header

    Returns:
        File type string or None
    """
    for file_type, info in MAGIC_BYTES.items():
        if data.startswith(info['header']):
            return file_type

    # Special case for TAR (magic at offset 257)
    if len(data) > 262 and data[257:262] == b'ustar':
        return 'TAR'

    return None


def find_embedded_files(file_path: str) -> List[Dict]:
    """
    Find embedded files in a file.

    Args:
        file_path: Path to the file to analyze

    Returns:
        List of embedded file info dictionaries
    """
    with open(file_path, 'rb') as f:
        data = f.read()

    embedded = []

    for file_type, info in MAGIC_BYTES.items():
        header = info['header']
        footer = info['footer']

        # Find all occurrences of header
        pos = 0
        while True:
            idx = data.find(header, pos)
            if idx == -1:
                break

            # For the main file, skip if at position 0
            if idx == 0 and get_file_type(data) == file_type:
                pos = idx + len(header)
                continue

            # Try to find end of file
            end = len(data)
            if footer:
                footer_idx = data.find(footer, idx + len(header))
                if footer_idx != -1:
                    end = footer_idx + len(footer)

            embedded.append({
                'type': file_type,
                'offset': idx,
                'size': end - idx if footer else 'unknown',
                'extension': info['extension'],
            })

            pos = idx + len(header)

    return embedded


def carve_file(source_path: str, offset: int, size: Optional[int] = None,
               output_path: Optional[str] = None) -> str:
    """
    Extract embedded file from source.

    Args:
        source_path: Path to source file
        offset: Byte offset of embedded file
        size: Size to extract (None = to end of file)
        output_path: Output file path (auto-generated if None)

    Returns:
        Path to extracted file
    """
    with open(source_path, 'rb') as f:
        f.seek(offset)
        if size:
            data = f.read(size)
        else:
            data = f.read()

    # Determine file type and extension
    file_type = get_file_type(data)
    if file_type and not output_path:
        ext = MAGIC_BYTES[file_type]['extension']
        output_path = f"carved_{offset}{ext}"
    elif not output_path:
        output_path = f"carved_{offset}.bin"

    with open(output_path, 'wb') as f:
        f.write(data)

    return output_path


def binwalk_extract(file_path: str, output_dir: str = "./extracted") -> List[str]:
    """
    Use binwalk to extract embedded files.

    Args:
        file_path: Path to file to analyze
        output_dir: Directory for extracted files

    Returns:
        List of extracted file paths
    """
    try:
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        result = subprocess.run(
            ["binwalk", "-e", "-C", output_dir, file_path],
            capture_output=True,
            text=True,
            timeout=60
        )

        # Find extracted files
        extracted = []
        for path in Path(output_dir).rglob('*'):
            if path.is_file():
                extracted.append(str(path))

        return extracted
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"binwalk error: {e}")
        return []


def foremost_extract(file_path: str, output_dir: str = "./foremost_output") -> List[str]:
    """
    Use foremost to carve files.

    Args:
        file_path: Path to file to analyze
        output_dir: Directory for extracted files

    Returns:
        List of extracted file paths
    """
    try:
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        subprocess.run(
            ["foremost", "-i", file_path, "-o", output_dir],
            capture_output=True,
            timeout=120
        )

        # Find extracted files
        extracted = []
        for path in Path(output_dir).rglob('*'):
            if path.is_file() and path.name != 'audit.txt':
                extracted.append(str(path))

        return extracted
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"foremost error: {e}")
        return []


def extract_all(file_path: str, output_dir: str = "./extracted") -> Dict[str, List[str]]:
    """
    Extract all embedded files using multiple methods.

    Args:
        file_path: Path to file to analyze
        output_dir: Directory for extracted files

    Returns:
        Dictionary mapping method to list of extracted files
    """
    results = {}

    # Use binwalk
    binwalk_files = binwalk_extract(file_path, f"{output_dir}/binwalk")
    if binwalk_files:
        results['binwalk'] = binwalk_files

    # Use manual carving
    embedded = find_embedded_files(file_path)
    carved_files = []
    for i, emb in enumerate(embedded):
        if isinstance(emb['size'], int):
            out_path = f"{output_dir}/carved_{i}{emb['extension']}"
            carve_file(file_path, emb['offset'], emb['size'], out_path)
            carved_files.append(out_path)
    if carved_files:
        results['carved'] = carved_files

    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        print(f"Analyzing: {file_path}")

        embedded = find_embedded_files(file_path)
        if embedded:
            print("\nEmbedded files found:")
            for e in embedded:
                print(f"  {e['type']} at offset {e['offset']} ({e['size']} bytes)")
        else:
            print("No embedded files found with simple scan")
            print("Try: binwalk -e " + file_path)
