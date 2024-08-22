---
layout:	post
title:  "PE Header: MS DOS Header, MS DOS Stub & Rich Header"
date:   2024-08-22 11:11:11 +0200
tags: [PE]
---

## PE Header: DOS Header

![PE Illustration](/images/2024-08-22-File_Format-PE-Header-I/1.jpg)

The PE file format starts with DOS header. The DOS header has been part of PE file format since v2 of MS-DOS operating system, but still have been kept for backward compatibility. 

**Example:** If older OS like MS-DOS tries to load newer executable, the system will output error message from MS DOS Stub to prevent crash. The MS DOS Stub will be covered in next section. 

The DOS header is 64-byte long structure, which is described below.

```c
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

The important ones from the above structure are:

- `e_magic`: It is 2-byte value that points to the magic number, i.e. `MZ` or `0x4D5A`. So it is also referred as MZ header.
- `e_lfanew`: It is a 4-byte value that points to the offset of `PE` or `0x5045` (Signature of NT Header). When OS loader tries to load and execute a PE file, it checks this value to ensure that its a valid PE file. Also this value help OS loader to locate the starting offset of NT Header, which holds other crucial information.

Lets now verify with PE-Bear. You can load `C:\Windows\System32\calc.exe` in the PE-Bear to follow along.

![PE-Bear DOS Header](/images/2024-08-22-File_Format-PE-Header-I/2.jpg)

Here, the `e_magic`  can be seen as ‘Magic number’ which value is `0x5A4D`. But if you check the above hex view, the value is `0x4D5A`. This is due to endianness, which dictates the order of sequence of bytes. 

- **Note:** In memory, values are stored in little-endian format, while on disk, in networks, or in registers, big-endian format is used.
- The `0x5A4D` is little endian because the PE-Bear reads the value from memory.

Also, the `e_lfanew` can be seen as ‘File address of new exe header’, which value is `E8`. If we check the E8 offset on above hex view format, the value is `0x5045` or `PE`.

<br>

## PE Header: MS DOS Stub 

![PE Illustration](/images/2024-08-22-File_Format-PE-Header-I/3.jpg)

As mentioned above, if older OS like MS-DOS tries to load newer executable, the system will output error message from MS DOS Stub and exit. 

The message is `This program cannot be run in DOS mode.` , which can be seen in PE-Bear below.

![PE-Bear](/images/2024-08-22-File_Format-PE-Header-I/4.jpg)

<br>

## PE Header: Rich Header

![PE Illustration](/images/2024-08-22-File_Format-PE-Header-I/5.jpg)

Immediately after the MS DOS Stub and before the start of NT Header, there is Rich Header. The Rich Header is present only on PE files built using Microsoft Visual Studio. 

The Rich Header consist of XORed encrypted data followed by `Rich` signature and a 4-byte Checksum (XOR key). The XORed encrypted data consist of `DanS`  signature, followed by padding and then metadata entries, which holds ProductId, BuildId, use Count and Visual Studio version.

Lets now verify with PE-Bear.

![PE-Bear](/images/2024-08-22-File_Format-PE-Header-I/6.jpg)

Here, the Rich Header is highlighted in the hex view. The values before `Rich` signature or `0x52696368`  is XORed encrypted. The value after `0x52696368`  is the Checksum (XOR key), which is `0xFBBD959B`.

Using the XOR key as `0xFBBD959B` , the XORed encrypted value is decrypted using the CyberChef.

![CyberChef](/images/2024-08-22-File_Format-PE-Header-I/7.jpg)

In the decrypted content, the `DanS` signature can be seen. Following it contain the metadata mentioned above.

The XOR decryption and parsing of the decrypted values is done automatically by PE-Bear, which can be seen below. Again, note that the hex values are in little-endian.

![PE-Bear](/images/2024-08-22-File_Format-PE-Header-I/8.jpg)

All the metadata like ProductId, BuildId, use Count and Visual Studio version can be seen.