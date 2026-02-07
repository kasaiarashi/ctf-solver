# Forensics Cheatsheet

## First Things to Run (Any File)

```bash
# Always start with these
file <filename>                    # Identify file type
exiftool <filename>                # Extract metadata
strings <filename> | head -100     # Find readable strings
strings <filename> | grep -i flag  # Quick flag search
xxd <filename> | head -50          # Hex dump
binwalk <filename>                 # Find embedded files
binwalk -e <filename>              # Extract embedded files
```

---

## Image Files (PNG, JPG, GIF, BMP)

### Initial Analysis
```bash
file image.png
exiftool image.png
pngcheck image.png                 # PNG integrity check
identify -verbose image.png        # ImageMagick details
```

### Steganography Detection
```bash
# PNG
zsteg image.png                    # LSB and other techniques
zsteg -a image.png                 # Try all methods
pngcheck -v image.png              # Check for appended data

# JPEG
steghide info image.jpg            # Check for steghide data
steghide extract -sf image.jpg     # Extract (may need password)
stegseek image.jpg wordlist.txt    # Bruteforce steghide password
outguess -r image.jpg output.txt   # Outguess extraction

# General
stegsolve                          # GUI tool for bit plane analysis
foremost image.png                 # Carve embedded files
```

### Check for Hidden Data
```bash
# Appended data after image
binwalk image.png
tail -c 1000 image.png | xxd       # Check end of file

# LSB extraction (manual)
python3 -c "
from PIL import Image
img = Image.open('image.png')
pixels = list(img.getdata())
bits = ''.join(str(p[0] & 1) for p in pixels[:1000])
print(bits)
"
```

### Metadata Secrets
```bash
exiftool -a -u -g1 image.jpg       # All metadata, grouped
exiftool -Comment image.jpg        # Check comment field
exiftool -UserComment image.jpg    # Check user comment
```

---

## Audio Files (WAV, MP3, FLAC)

### Initial Analysis
```bash
file audio.wav
exiftool audio.wav
mediainfo audio.wav
ffprobe audio.wav
```

### Spectrogram Analysis
```bash
# Check for hidden images in spectrogram
sox audio.wav -n spectrogram -o spec.png
audacity                           # Visual spectrogram analysis
```

### Audio Steganography
```bash
steghide info audio.wav
steghide extract -sf audio.wav
sonic-visualiser audio.wav         # Detailed analysis
```

### DTMF/Morse Decoding
```bash
multimon-ng -t wav audio.wav       # Decode DTMF tones
# For Morse code - use audacity or online decoder
```

---

## Archive Files (ZIP, RAR, 7Z, TAR)

### Initial Analysis
```bash
file archive.zip
unzip -l archive.zip               # List contents
zipinfo archive.zip                # Detailed info
7z l archive.7z                    # List 7z contents
```

### Password Cracking
```bash
# ZIP
zip2john archive.zip > hash.txt
john hash.txt --wordlist=rockyou.txt
fcrackzip -u -D -p rockyou.txt archive.zip

# RAR
rar2john archive.rar > hash.txt
john hash.txt --wordlist=rockyou.txt

# 7z
7z2john archive.7z > hash.txt
john hash.txt
```

### Corrupted Archives
```bash
zip -FF archive.zip --out fixed.zip    # Fix corrupted ZIP
unzip -p archive.zip                   # Ignore errors, extract to stdout
```

---

## PDF Files

### Initial Analysis
```bash
file document.pdf
pdfinfo document.pdf
exiftool document.pdf
strings document.pdf | grep -i flag
```

### Extract Content
```bash
pdftotext document.pdf             # Extract text
pdfimages -all document.pdf img    # Extract images
pdf-parser.py document.pdf         # Parse structure
peepdf document.pdf                # Interactive analysis
```

### Hidden Content
```bash
# Check for JavaScript
pdf-parser.py --search javascript document.pdf

# Check for embedded files
pdf-parser.py --search /EmbeddedFile document.pdf
binwalk document.pdf
```

---

## Network Captures (PCAP)

### Initial Analysis
```bash
file capture.pcap
capinfos capture.pcap              # Capture statistics
tshark -r capture.pcap | head -50  # Quick overview
```

### Common Extractions
```bash
# HTTP objects (files)
tshark -r capture.pcap --export-objects http,./http_files/

# Follow TCP streams
tshark -r capture.pcap -z follow,tcp,ascii,0

# Extract credentials
tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e http.file_data

# DNS queries
tshark -r capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | sort -u

# FTP files
tshark -r capture.pcap -Y "ftp-data" -T fields -e data
```

### Wireshark Filters
```bash
# HTTP traffic
http

# Specific IP
ip.addr == 192.168.1.1

# TCP port
tcp.port == 4444

# Contains string
frame contains "flag"
http contains "password"

# POST requests
http.request.method == "POST"
```

### Extract Files
```bash
# Foremost on pcap
foremost -i capture.pcap -o carved/

# NetworkMiner (GUI)
networkminer capture.pcap

# tcpflow - extract TCP streams
tcpflow -r capture.pcap -o output/
```

---

## Memory Dumps

### Volatility 2
```bash
# Identify profile
volatility -f dump.raw imageinfo

# Process list
volatility -f dump.raw --profile=Win7SP1x64 pslist
volatility -f dump.raw --profile=Win7SP1x64 pstree

# Command history
volatility -f dump.raw --profile=Win7SP1x64 cmdscan
volatility -f dump.raw --profile=Win7SP1x64 consoles

# Network connections
volatility -f dump.raw --profile=Win7SP1x64 netscan

# Files
volatility -f dump.raw --profile=Win7SP1x64 filescan | grep -i flag
volatility -f dump.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000 -D output/

# Registry
volatility -f dump.raw --profile=Win7SP1x64 hivelist
volatility -f dump.raw --profile=Win7SP1x64 hashdump

# Browser history
volatility -f dump.raw --profile=Win7SP1x64 iehistory
```

### Volatility 3
```bash
vol3 -f dump.raw windows.info
vol3 -f dump.raw windows.pslist
vol3 -f dump.raw windows.pstree
vol3 -f dump.raw windows.cmdline
vol3 -f dump.raw windows.filescan
vol3 -f dump.raw windows.dumpfiles --physaddr 0x000000
```

### Strings Search
```bash
strings dump.raw | grep -i password
strings dump.raw | grep -i flag
strings -el dump.raw | grep -i flag  # Unicode (little endian)
```

---

## Disk Images

### Mount and Explore
```bash
# List partitions
fdisk -l disk.img
mmls disk.img

# Mount
mount -o loop,offset=$((512*2048)) disk.img /mnt/

# File listing
fls disk.img
fls -r disk.img                    # Recursive

# Extract file by inode
icat disk.img 1234 > extracted_file
```

### Deleted Files
```bash
# Recover deleted files
photorec disk.img
extundelete disk.img --restore-all
testdisk disk.img
```

### Filesystem Timeline
```bash
fls -m "/" -r disk.img > bodyfile.txt
mactime -b bodyfile.txt > timeline.txt
```

---

## QR Codes & Barcodes

```bash
# Decode QR
zbarimg image.png

# If damaged, try
zbarimg --raw image.png

# Multiple QR codes
zbarimg -q image.png
```

---

## Common Flag Locations

```bash
# Search everywhere
grep -r "flag{" .
grep -r "CTF{" .
strings * | grep -iE "(flag|ctf)\{"

# Hidden in metadata
exiftool * | grep -i flag

# Encoded flags
strings * | base64 -d 2>/dev/null | grep flag
```

---

## Useful One-Liners

```bash
# Extract all strings and decode base64
strings file | while read line; do echo "$line" | base64 -d 2>/dev/null; done | grep flag

# Find files by magic bytes
find . -exec file {} \; | grep "PNG image"

# Recursive binwalk
find . -type f -exec binwalk {} \;

# Check all files for embedded archives
for f in *; do binwalk "$f"; done
```
