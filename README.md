# FAT32 File Recovery

## Overview

**fat32-undelete** is a command-line utility written in C that directly parses and manipulates a raw FAT32 disk image to recover deleted files from the root directory. I learned and gained the skills to complete this project from my operating systems course. It supports:

- Printing basic FAT32 filesystem information  
- Listing all valid entries in the root directory  
- Recovering a deleted file under two scenarios:  
  1. **Contiguously allocated** (simple “undelete”)  
  2. **Possibly non-contiguous** (brute-forces cluster permutations with a SHA-1 checksum)  

By bypassing the operating system’s filesystem drivers and working purely “byte-level” against the disk image, this tool illustrates how FAT32 structures—Boot Sector, FAT tables, directory entries, and clusters—are laid out on disk, and how a file’s contents can be restored after deletion.

## Tech Stack

- **Language**  
  - C (compiled with `gcc -std=c11`)  
- **Libraries**  
  - `<unistd.h>`, `<fcntl.h>`, `<stdint.h>`, etc., for low-level I/O and data types  
  - **OpenSSL’s libcrypto** (`-lcrypto`) to compute SHA-1 hashes  
- **Build Tools**  
  - `gcc` (or any POSIX-compatible C compiler)  
  - `make` (optional, if you choose to create a Makefile)  
- **Runtime Environment**  
  - Linux (or any UNIX-like OS)  
  - Disk images created/formatted with `mkfs.fat -F 32`  
  - Assumes little-endian architecture (x86_64, etc.)  

## Features

1. **Print Filesystem Info** (`-i`)  
   - Number of FATs  
   - Bytes per sector  
   - Sectors per cluster  
   - Number of reserved sectors  

2. **List Root Directory** (`-l`)  
   - Skips deleted and long-filename (LFN) entries  
   - Prints each entry with:  
     - `<NAME.EXT> (size = <bytes>, starting cluster = <cluster#>)` for files  
     - `<DIRNAME>/ (starting cluster = <cluster#>)` for directories  
   - Displays `Total number of entries = <n>`  

3. **Recover Contiguously Allocated File** (`-r <FILENAME> [-s <SHA1>]`)  
   - Finds a deleted directory entry (first byte = `0xE5`) matching the 8.3 name  
   - If only one candidate exists, restores it by:  
     1. Rewriting the directory entry’s first byte (replacing `0xE5` with original letter)  
     2. Rebuilding a contiguous FAT chain (`clus → clus+1 → … → EOC`) for the file’s size  
   - If multiple candidates match and no `-s` flag is provided, reports **“multiple candidates found”**  
   - With `-s <SHA1>`:  
     - Computes each candidate’s content via its old cluster chain  
     - Compares SHA-1 hash to the user’s fingerprint  
     - Restores only the matching entry, or prints **“file not found”** if none match  

4. **Recover Possibly Non-Contiguous File** (`-R <FILENAME> -s <SHA1>`)  
   - Gathers all deleted 8.3 entries matching `<FILENAME>`  
   - For each candidate with `file_size` spanning ≤ 5 clusters, brute-forces all permutations of free clusters among cluster #2…#21:  
     1. Reads exactly `file_size` bytes from each cluster in that order  
     2. Computes SHA-1; if it matches, stops  
   - Once a matching permutation is found:  
     1. Restores the directory entry’s first byte  
     2. Writes each cluster’s FAT entry to point to the next, ending in EOC  
     3. Prints **“successfully recovered with SHA-1”**  
   - If no candidate → **“file not found”**

---

## Key Takeaways

- **FAT32 Internals**  
  - Boot Sector fields (bytes/sector, sectors/cluster, reserved sectors, FAT size, root cluster) drive all offset calculations.  
  - The root directory on FAT32 is just another cluster chain (unlike FAT12/16, where it’s a fixed table).  

- **Raw Disk Access & Byte-Level Manipulation**  
  - Uses `pread()`/`pwrite()` to read and write specific offsets in the disk image (no OS filesystem calls).  
  - Matches a deleted entry by checking `DIR_Name[0] == 0xE5` (the deleted marker) and comparing the remaining 10 bytes.  
  - Computes exact offsets:  
    ```c
    FirstFATOffsetBytes = reserved_sectors × bytes_per_sector;
    FirstDataOffsetBytes = (reserved_sectors + numFATs × sectorsPerFAT) × bytes_per_sector;
    cluster_offset = FirstDataOffsetBytes + (cluster - 2) × (bytes_per_sector × sectors_per_cluster);
    ```

- **SHA-1 Integration**  
  - Uses OpenSSL’s `SHA1()` to compute a 20-byte fingerprint of candidate files.  
  - Disambiguates multiple deletion candidates by matching their on-disk content to a known SHA-1.  

- **Brute-Force Permutations**  
  - For non-contiguous recovery, generates all k-length permutations of free clusters (limited to clusters #2…#21 and k ≤ 5).  
  - Reads partial clusters and concatenates bytes to recompute SHA-1 until a match is found.

- **Error Handling & Usability**  
  - Clear, verbatim usage message if arguments are invalid.  
  - Graceful reporting: **“file not found”** or **“multiple candidates found”** when appropriate.  
  - Assumes disk image is unmounted and that you test only 8.3–compliant filenames.



## Usage

- **Linux (or UNIX-like)** with `gcc` and OpenSSL development headers installed  
- Create or obtain a raw FAT32 image (e.g., with `dd` + `mkfs.fat`).



```bash
git clone https://github.com/<your-username>/fat32-undelete.git
cd fat32-undelete
gcc -std=c11 -Wall -Wextra -o nyufile nyufile.c -lcrypto
