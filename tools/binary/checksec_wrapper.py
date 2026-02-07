"""
Checksec Wrapper

Parse and analyze binary security features.
"""

import subprocess
import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class Protections:
    """Binary protection status."""
    arch: str = ""
    relro: str = ""
    stack_canary: bool = False
    nx: bool = False
    pie: bool = False
    rpath: bool = False
    runpath: bool = False
    fortify: bool = False
    stripped: bool = False


def checksec(binary_path: str) -> Protections:
    """
    Run checksec on a binary and parse the results.

    Args:
        binary_path: Path to the binary file

    Returns:
        Protections object with security feature status
    """
    try:
        result = subprocess.run(
            ["checksec", "--file=" + binary_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        output = result.stdout + result.stderr
        return _parse_checksec_output(output)
    except FileNotFoundError:
        # checksec not installed, try with pwntools
        return _checksec_pwntools(binary_path)
    except subprocess.TimeoutExpired:
        return Protections()


def _parse_checksec_output(output: str) -> Protections:
    """Parse checksec command output."""
    prot = Protections()

    # Architecture
    arch_match = re.search(r'Arch:\s*(\S+)', output)
    if arch_match:
        prot.arch = arch_match.group(1)

    # RELRO
    if "Full RELRO" in output:
        prot.relro = "Full"
    elif "Partial RELRO" in output:
        prot.relro = "Partial"
    else:
        prot.relro = "None"

    # Stack Canary
    prot.stack_canary = "Canary found" in output

    # NX
    prot.nx = "NX enabled" in output

    # PIE
    prot.pie = "PIE enabled" in output

    # Stripped
    prot.stripped = "No Symbols" in output or "stripped" in output.lower()

    return prot


def _checksec_pwntools(binary_path: str) -> Protections:
    """Use pwntools to check binary protections."""
    try:
        from pwn import ELF
        elf = ELF(binary_path, checksec=False)

        prot = Protections()
        prot.arch = elf.arch
        prot.relro = "Full" if elf.relro == "Full" else ("Partial" if elf.relro else "None")
        prot.stack_canary = elf.canary
        prot.nx = elf.nx
        prot.pie = elf.pie

        return prot
    except ImportError:
        return Protections()


def get_protections(binary_path: str) -> dict:
    """
    Get binary protections as a dictionary.

    Args:
        binary_path: Path to the binary

    Returns:
        Dictionary with protection status
    """
    prot = checksec(binary_path)
    return {
        "arch": prot.arch,
        "relro": prot.relro,
        "canary": prot.stack_canary,
        "nx": prot.nx,
        "pie": prot.pie,
        "stripped": prot.stripped,
    }


def print_protections(binary_path: str) -> None:
    """Print binary protections in a readable format."""
    prot = checksec(binary_path)
    print(f"Binary: {binary_path}")
    print(f"  Arch:    {prot.arch}")
    print(f"  RELRO:   {prot.relro}")
    print(f"  Canary:  {'✓' if prot.stack_canary else '✗'}")
    print(f"  NX:      {'✓' if prot.nx else '✗'}")
    print(f"  PIE:     {'✓' if prot.pie else '✗'}")
    print(f"  Stripped: {'✓' if prot.stripped else '✗'}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print_protections(sys.argv[1])
