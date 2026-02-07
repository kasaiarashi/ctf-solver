"""
ELF Analyzer

Analyze ELF binary structure, symbols, and sections.
"""

import subprocess
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class Symbol:
    """An ELF symbol."""
    name: str
    address: int
    size: int
    symbol_type: str
    section: str


@dataclass
class Section:
    """An ELF section."""
    name: str
    address: int
    size: int
    section_type: str


@dataclass
class ELFInfo:
    """Complete ELF analysis."""
    arch: str
    bits: int
    endian: str
    entry_point: int
    sections: List[Section]
    symbols: List[Symbol]
    got: Dict[str, int]
    plt: Dict[str, int]


def analyze_elf(binary_path: str) -> ELFInfo:
    """
    Perform complete ELF analysis.

    Args:
        binary_path: Path to the ELF binary

    Returns:
        ELFInfo object with complete analysis
    """
    try:
        from pwn import ELF
        elf = ELF(binary_path, checksec=False)

        symbols = []
        for name, addr in elf.symbols.items():
            symbols.append(Symbol(name, addr, 0, "FUNC", ""))

        sections = []
        for name, section in elf.sections.items():
            if hasattr(section, 'header'):
                sections.append(Section(
                    name,
                    section.header.sh_addr,
                    section.header.sh_size,
                    ""
                ))

        return ELFInfo(
            arch=elf.arch,
            bits=elf.bits,
            endian="little" if elf.endian == "little" else "big",
            entry_point=elf.entry,
            sections=sections,
            symbols=symbols,
            got=dict(elf.got),
            plt=dict(elf.plt),
        )
    except ImportError:
        return _analyze_elf_native(binary_path)


def _analyze_elf_native(binary_path: str) -> ELFInfo:
    """Analyze ELF using system tools."""
    info = ELFInfo(
        arch="",
        bits=0,
        endian="",
        entry_point=0,
        sections=[],
        symbols=[],
        got={},
        plt={},
    )

    # Get basic info with readelf
    try:
        result = subprocess.run(
            ["readelf", "-h", binary_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        for line in result.stdout.split('\n'):
            if "Class:" in line:
                info.bits = 64 if "ELF64" in line else 32
            elif "Machine:" in line:
                if "X86-64" in line:
                    info.arch = "amd64"
                elif "80386" in line:
                    info.arch = "i386"
                elif "ARM" in line:
                    info.arch = "arm"
            elif "Entry point" in line:
                match = re.search(r'0x([0-9a-fA-F]+)', line)
                if match:
                    info.entry_point = int(match.group(1), 16)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return info


def get_symbols(binary_path: str) -> Dict[str, int]:
    """
    Get all symbols and their addresses.

    Args:
        binary_path: Path to the binary

    Returns:
        Dictionary mapping symbol names to addresses
    """
    try:
        from pwn import ELF
        elf = ELF(binary_path, checksec=False)
        return dict(elf.symbols)
    except ImportError:
        symbols = {}
        try:
            result = subprocess.run(
                ["nm", binary_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            for line in result.stdout.split('\n'):
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        addr = int(parts[0], 16)
                        name = parts[2]
                        symbols[name] = addr
                    except ValueError:
                        continue
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return symbols


def get_got_plt(binary_path: str) -> Tuple[Dict[str, int], Dict[str, int]]:
    """
    Get GOT and PLT entries.

    Args:
        binary_path: Path to the binary

    Returns:
        Tuple of (GOT dict, PLT dict)
    """
    try:
        from pwn import ELF
        elf = ELF(binary_path, checksec=False)
        return dict(elf.got), dict(elf.plt)
    except ImportError:
        return {}, {}


def find_function(binary_path: str, func_name: str) -> Optional[int]:
    """
    Find a function's address.

    Args:
        binary_path: Path to the binary
        func_name: Function name to find

    Returns:
        Function address or None
    """
    symbols = get_symbols(binary_path)
    return symbols.get(func_name)


def find_string(binary_path: str, string: str) -> List[int]:
    """
    Find addresses of a string in the binary.

    Args:
        binary_path: Path to the binary
        string: String to search for

    Returns:
        List of addresses where string is found
    """
    try:
        from pwn import ELF
        elf = ELF(binary_path, checksec=False)
        return list(elf.search(string.encode()))
    except ImportError:
        # Use strings and grep as fallback
        addresses = []
        try:
            result = subprocess.run(
                ["strings", "-t", "x", binary_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            for line in result.stdout.split('\n'):
                if string in line:
                    match = re.match(r'\s*([0-9a-fA-F]+)', line)
                    if match:
                        addresses.append(int(match.group(1), 16))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return addresses


def get_dangerous_functions(binary_path: str) -> Dict[str, int]:
    """
    Find dangerous functions that might be exploitable.

    Returns:
        Dictionary of dangerous function names to their PLT addresses
    """
    dangerous = [
        "gets", "strcpy", "strcat", "sprintf", "scanf",
        "vsprintf", "printf", "system", "execve"
    ]

    _, plt = get_got_plt(binary_path)
    return {name: addr for name, addr in plt.items() if name in dangerous}


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        binary = sys.argv[1]
        print(f"Analyzing {binary}...")

        info = analyze_elf(binary)
        print(f"\nArchitecture: {info.arch}")
        print(f"Bits: {info.bits}")
        print(f"Entry point: 0x{info.entry_point:x}")

        dangerous = get_dangerous_functions(binary)
        if dangerous:
            print("\nDangerous functions:")
            for name, addr in dangerous.items():
                print(f"  {name}: 0x{addr:x}")
