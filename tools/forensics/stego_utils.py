"""
Steganography Utilities

Tools for detecting and extracting hidden data in images and files.
"""

import subprocess
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path


def extract_lsb(image_path: str, bits: int = 1) -> bytes:
    """
    Extract LSB (Least Significant Bit) data from an image.

    Args:
        image_path: Path to the image file
        bits: Number of LSBs to extract (1-8)

    Returns:
        Extracted bytes
    """
    try:
        from PIL import Image
    except ImportError:
        print("PIL not available, trying zsteg...")
        return _zsteg_extract(image_path)

    img = Image.open(image_path)
    pixels = list(img.getdata())

    extracted_bits = []

    # Extract from each color channel
    for pixel in pixels:
        if isinstance(pixel, int):
            # Grayscale
            for b in range(bits):
                extracted_bits.append((pixel >> b) & 1)
        else:
            # RGB/RGBA
            for channel in pixel[:3]:  # RGB only
                for b in range(bits):
                    extracted_bits.append((channel >> b) & 1)

    # Convert bits to bytes
    extracted_bytes = bytearray()
    for i in range(0, len(extracted_bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte |= extracted_bits[i + j] << j
        extracted_bytes.append(byte)

    return bytes(extracted_bytes)


def _zsteg_extract(image_path: str) -> bytes:
    """Use zsteg to extract hidden data."""
    try:
        result = subprocess.run(
            ["zsteg", "-a", image_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout.encode()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return b""


def check_file_signature(file_path: str) -> Tuple[str, bool]:
    """
    Check if file signature matches extension.

    Args:
        file_path: Path to the file

    Returns:
        Tuple of (detected_type, matches_extension)
    """
    signatures = {
        b'\x89PNG\r\n\x1a\n': ('PNG', ['.png']),
        b'\xff\xd8\xff': ('JPEG', ['.jpg', '.jpeg']),
        b'GIF87a': ('GIF', ['.gif']),
        b'GIF89a': ('GIF', ['.gif']),
        b'PK\x03\x04': ('ZIP', ['.zip', '.docx', '.xlsx', '.jar', '.apk']),
        b'%PDF': ('PDF', ['.pdf']),
        b'\x7fELF': ('ELF', ['', '.elf', '.so', '.o']),
        b'MZ': ('EXE', ['.exe', '.dll']),
        b'Rar!\x1a\x07': ('RAR', ['.rar']),
        b'\x1f\x8b': ('GZIP', ['.gz', '.tgz']),
        b'BZh': ('BZIP2', ['.bz2']),
        b'\xfd7zXZ\x00': ('XZ', ['.xz']),
        b'RIFF': ('RIFF', ['.wav', '.avi', '.webp']),
        b'\x00\x00\x00\x1cftyp': ('MP4', ['.mp4', '.m4a', '.m4v']),
        b'\x00\x00\x00\x18ftyp': ('MP4', ['.mp4', '.m4a', '.m4v']),
        b'\x00\x00\x00\x20ftyp': ('MP4', ['.mp4', '.m4a', '.m4v']),
    }

    with open(file_path, 'rb') as f:
        header = f.read(32)

    detected = 'Unknown'
    expected_exts = []

    for sig, (file_type, exts) in signatures.items():
        if header.startswith(sig):
            detected = file_type
            expected_exts = exts
            break

    # Check extension
    ext = Path(file_path).suffix.lower()
    matches = ext in expected_exts or not expected_exts

    return detected, matches


def analyze_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract metadata from a file using exiftool.

    Args:
        file_path: Path to the file

    Returns:
        Dictionary of metadata
    """
    try:
        result = subprocess.run(
            ["exiftool", "-j", file_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        import json
        data = json.loads(result.stdout)
        return data[0] if data else {}
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        return {}


def find_hidden_data(file_path: str) -> List[Dict[str, Any]]:
    """
    Search for hidden data in a file using multiple techniques.

    Args:
        file_path: Path to the file

    Returns:
        List of findings
    """
    findings = []

    # Check file signature
    detected, matches = check_file_signature(file_path)
    if not matches:
        findings.append({
            "type": "signature_mismatch",
            "message": f"File appears to be {detected} but extension doesn't match",
        })

    # Check for appended data
    appended = _check_appended_data(file_path)
    if appended:
        findings.append({
            "type": "appended_data",
            "message": f"Found {len(appended)} bytes after file end",
            "data": appended[:100],  # First 100 bytes
        })

    # Check metadata
    metadata = analyze_metadata(file_path)
    interesting_fields = ['Comment', 'UserComment', 'ImageDescription',
                          'Artist', 'Copyright', 'XPComment']
    for field in interesting_fields:
        if field in metadata and metadata[field]:
            findings.append({
                "type": "metadata",
                "field": field,
                "value": metadata[field],
            })

    # Run binwalk
    binwalk_results = _run_binwalk(file_path)
    if binwalk_results:
        findings.append({
            "type": "binwalk",
            "message": "Embedded files detected",
            "results": binwalk_results,
        })

    return findings


def _check_appended_data(file_path: str) -> Optional[bytes]:
    """Check for data appended after file end marker."""
    with open(file_path, 'rb') as f:
        content = f.read()

    # PNG end marker
    png_end = b'\x49\x45\x4e\x44\xae\x42\x60\x82'
    if content.startswith(b'\x89PNG'):
        idx = content.find(png_end)
        if idx != -1 and idx + len(png_end) < len(content):
            return content[idx + len(png_end):]

    # JPEG end marker
    if content.startswith(b'\xff\xd8'):
        idx = content.rfind(b'\xff\xd9')
        if idx != -1 and idx + 2 < len(content):
            return content[idx + 2:]

    return None


def _run_binwalk(file_path: str) -> List[str]:
    """Run binwalk to detect embedded files."""
    try:
        result = subprocess.run(
            ["binwalk", file_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        lines = result.stdout.strip().split('\n')
        # Skip header lines
        return [l for l in lines[3:] if l.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def extract_strings(file_path: str, min_length: int = 4) -> List[str]:
    """
    Extract printable strings from a file.

    Args:
        file_path: Path to the file
        min_length: Minimum string length

    Returns:
        List of strings found
    """
    try:
        result = subprocess.run(
            ["strings", "-n", str(min_length), file_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout.strip().split('\n')
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Fallback to Python implementation
        with open(file_path, 'rb') as f:
            content = f.read()

        strings = []
        current = []
        for byte in content:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []

        if len(current) >= min_length:
            strings.append(''.join(current))

        return strings


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        print(f"Analyzing: {file_path}")

        detected, matches = check_file_signature(file_path)
        print(f"Detected type: {detected}")
        print(f"Signature matches: {matches}")

        findings = find_hidden_data(file_path)
        if findings:
            print("\nFindings:")
            for f in findings:
                print(f"  - {f['type']}: {f.get('message', f)}")
