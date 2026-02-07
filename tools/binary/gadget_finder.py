"""
Gadget Finder

Find ROP gadgets in binaries.
"""

import subprocess
import re
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class Gadget:
    """A ROP gadget."""
    address: int
    instructions: str

    def __str__(self):
        return f"0x{self.address:x}: {self.instructions}"


def find_gadgets(binary_path: str, max_depth: int = 10) -> List[Gadget]:
    """
    Find all ROP gadgets in a binary.

    Args:
        binary_path: Path to the binary
        max_depth: Maximum gadget instruction depth

    Returns:
        List of Gadget objects
    """
    gadgets = []

    # Try ROPgadget first
    try:
        result = subprocess.run(
            ["ROPgadget", "--binary", binary_path, "--depth", str(max_depth)],
            capture_output=True,
            text=True,
            timeout=60
        )
        gadgets = _parse_ropgadget_output(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Try ropper as fallback
        try:
            result = subprocess.run(
                ["ropper", "-f", binary_path, "--nocolor"],
                capture_output=True,
                text=True,
                timeout=60
            )
            gadgets = _parse_ropper_output(result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return gadgets


def _parse_ropgadget_output(output: str) -> List[Gadget]:
    """Parse ROPgadget output."""
    gadgets = []
    for line in output.split('\n'):
        match = re.match(r'(0x[0-9a-fA-F]+)\s*:\s*(.+)', line)
        if match:
            addr = int(match.group(1), 16)
            instr = match.group(2).strip()
            gadgets.append(Gadget(addr, instr))
    return gadgets


def _parse_ropper_output(output: str) -> List[Gadget]:
    """Parse ropper output."""
    gadgets = []
    for line in output.split('\n'):
        match = re.match(r'(0x[0-9a-fA-F]+):\s*(.+)', line)
        if match:
            addr = int(match.group(1), 16)
            instr = match.group(2).strip()
            gadgets.append(Gadget(addr, instr))
    return gadgets


def find_specific_gadget(binary_path: str, pattern: str) -> List[Gadget]:
    """
    Find gadgets matching a specific pattern.

    Args:
        binary_path: Path to the binary
        pattern: Regex pattern to match (e.g., "pop rdi")

    Returns:
        List of matching Gadget objects
    """
    all_gadgets = find_gadgets(binary_path)
    regex = re.compile(pattern, re.IGNORECASE)
    return [g for g in all_gadgets if regex.search(g.instructions)]


def find_pop_gadgets(binary_path: str) -> Dict[str, Optional[Gadget]]:
    """
    Find common pop gadgets for ROP chains.

    Returns:
        Dictionary mapping register names to gadgets
    """
    gadgets = find_gadgets(binary_path)

    pop_gadgets = {
        "pop_rdi": None,
        "pop_rsi": None,
        "pop_rdx": None,
        "pop_rcx": None,
        "pop_rax": None,
        "pop_rbx": None,
    }

    for g in gadgets:
        instr = g.instructions.lower()
        # Look for clean gadgets (just pop + ret)
        if "pop rdi" in instr and "ret" in instr and pop_gadgets["pop_rdi"] is None:
            pop_gadgets["pop_rdi"] = g
        elif "pop rsi" in instr and "ret" in instr and pop_gadgets["pop_rsi"] is None:
            pop_gadgets["pop_rsi"] = g
        elif "pop rdx" in instr and "ret" in instr and pop_gadgets["pop_rdx"] is None:
            pop_gadgets["pop_rdx"] = g
        elif "pop rcx" in instr and "ret" in instr and pop_gadgets["pop_rcx"] is None:
            pop_gadgets["pop_rcx"] = g
        elif "pop rax" in instr and "ret" in instr and pop_gadgets["pop_rax"] is None:
            pop_gadgets["pop_rax"] = g
        elif "pop rbx" in instr and "ret" in instr and pop_gadgets["pop_rbx"] is None:
            pop_gadgets["pop_rbx"] = g

    return pop_gadgets


def find_syscall_gadget(binary_path: str) -> Optional[Gadget]:
    """Find a syscall gadget."""
    gadgets = find_gadgets(binary_path)
    for g in gadgets:
        if "syscall" in g.instructions.lower():
            return g
    return None


def find_ret_gadget(binary_path: str) -> Optional[Gadget]:
    """Find a simple ret gadget (useful for stack alignment)."""
    gadgets = find_gadgets(binary_path)
    for g in gadgets:
        if g.instructions.strip().lower() == "ret":
            return g
    return None


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        binary = sys.argv[1]
        print(f"Finding gadgets in {binary}...")

        # Find pop gadgets
        pops = find_pop_gadgets(binary)
        print("\nPop gadgets:")
        for name, gadget in pops.items():
            if gadget:
                print(f"  {name}: {gadget}")

        # Find syscall
        syscall = find_syscall_gadget(binary)
        if syscall:
            print(f"\nSyscall: {syscall}")
