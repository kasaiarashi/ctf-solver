#!/usr/bin/env python3
"""
PWN Exploit Template

Usage:
    python exploit.py          # Local
    python exploit.py REMOTE   # Remote
    python exploit.py GDB      # Debug with GDB
    python exploit.py DEBUG    # Debug output
"""

from pwn import *

# =============================================================================
# Configuration
# =============================================================================

BINARY = './challenge'
HOST = 'challenge.ctf.com'
PORT = 1337

# Load binary
elf = ELF(BINARY)
context.binary = elf

# Libc (uncomment and set if needed)
# libc = ELF('./libc.so.6')

# =============================================================================
# Helper Functions
# =============================================================================

def get_io():
    """Get IO handle based on command line arguments."""
    if args.REMOTE:
        return remote(HOST, PORT)
    elif args.GDB:
        return gdb.debug(BINARY, gdbscript='''
            # Add breakpoints here
            b main
            # b *0x401234
            continue
        ''')
    else:
        return process(BINARY)


def leak(name, addr):
    """Pretty print a leak."""
    log.info(f'{name}: {addr:#x}')
    return addr


# =============================================================================
# Exploit
# =============================================================================

def exploit(io):
    """
    Main exploitation logic.

    Vulnerability: [DESCRIBE VULNERABILITY]
    Strategy: [DESCRIBE EXPLOITATION STRATEGY]
    """

    # -------------------------------------------------------------------------
    # Stage 1: [Leak / Setup]
    # -------------------------------------------------------------------------

    # Example: Find offset
    # offset = cyclic_find(0x61616161)

    # Example: Get useful addresses
    # win = elf.symbols['win']
    # system_plt = elf.plt['system']
    # puts_plt = elf.plt['puts']
    # puts_got = elf.got['puts']

    # -------------------------------------------------------------------------
    # Stage 2: [Build Payload]
    # -------------------------------------------------------------------------

    payload = flat(
        # Example buffer overflow:
        # b'A' * offset,
        # p64(pop_rdi),
        # p64(binsh),
        # p64(system),
    )

    # -------------------------------------------------------------------------
    # Stage 3: [Send Payload]
    # -------------------------------------------------------------------------

    # io.sendline(payload)
    # io.send(payload)
    # io.sendafter(b'> ', payload)
    # io.sendlineafter(b'> ', payload)

    # -------------------------------------------------------------------------
    # Stage 4: [Get Flag]
    # -------------------------------------------------------------------------

    # io.interactive()
    # print(io.recvall().decode())

    pass


# =============================================================================
# Main
# =============================================================================

if __name__ == '__main__':
    # Set log level
    if args.DEBUG:
        context.log_level = 'debug'
    else:
        context.log_level = 'info'

    # Run exploit
    io = get_io()

    try:
        exploit(io)
        io.interactive()
    except EOFError:
        log.failure('Connection closed')
    except KeyboardInterrupt:
        log.warning('Interrupted')
    finally:
        io.close()
