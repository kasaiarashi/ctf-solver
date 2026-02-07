# Python Standards for CTF Tools

Guidelines for Python code in this project.

## Style

1. **Follow PEP 8** with these exceptions:
   - Line length: 100 characters max
   - Allow single-letter variables in exploit scripts for brevity

2. **Naming conventions**
   - Functions: `snake_case`
   - Classes: `PascalCase`
   - Constants: `UPPER_SNAKE_CASE`
   - Private: `_leading_underscore`

## Documentation

1. **Docstrings for all public functions**
   ```python
   def exploit_function(target: str, port: int) -> bool:
       """
       Short description.

       Args:
           target: Description of target
           port: Description of port

       Returns:
           Success status
       """
   ```

2. **Type hints** for function signatures

3. **Comments** for complex exploitation logic

## Imports

1. **Order**
   ```python
   # Standard library
   import os
   import sys

   # Third-party
   from pwn import *
   import requests

   # Local
   from tools.crypto import rsa_utils
   ```

2. **Prefer explicit imports**
   ```python
   # Good
   from pwn import remote, process, ELF

   # Acceptable in exploit scripts
   from pwn import *
   ```

## Error Handling

1. **Handle network errors**
   ```python
   try:
       io = remote(host, port)
   except Exception as e:
       log.failure(f"Connection failed: {e}")
       sys.exit(1)
   ```

2. **Graceful degradation**
   ```python
   try:
       from gmpy2 import iroot
   except ImportError:
       # Fallback to pure Python
       def iroot(n, k):
           ...
   ```

## Exploit Scripts

1. **Standard structure**
   ```python
   #!/usr/bin/env python3
   """Description and usage."""

   from pwn import *

   # Configuration
   BINARY = './challenge'
   HOST = 'host'
   PORT = 1337

   # Setup
   context.binary = ELF(BINARY)

   def exploit(io):
       """Main exploit logic."""
       pass

   if __name__ == '__main__':
       io = remote(HOST, PORT) if args.REMOTE else process(BINARY)
       exploit(io)
       io.interactive()
   ```

2. **Use pwntools conventions**
   - `args.REMOTE` for remote mode
   - `args.GDB` for debugging
   - `args.DEBUG` for verbose output

## Security

1. **Never hardcode**
   - Real credentials
   - API keys
   - Personal information

2. **Sanitize output**
   - Don't log sensitive data
   - Clear credentials after use
