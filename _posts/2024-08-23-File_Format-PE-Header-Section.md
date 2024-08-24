---
layout:	post
title:  "(V) PE Header: Section Header & PE Section"
date:   2024-08-22 10:11:11 +0200
categories: [Portable Executable (PE)]
tags: [PE]
---

---

## Section Header

![PE Illustration](/images/2024-08-22-File_Format-PE/1.png)

Immediately after the Optional Header is the Section Header, which structure is described below.

```c
typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize; 
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

Lets understand the important one. Other are documented here: [PE Format - Section Headers](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers)

- `Name`: This field specifies the name of the section and it is maximum 8 characters.
- `PhysicalAddress` or `VirtualSize`: This field is union that defines multiple names for same thing and specifies the size of section after loaded in memory.
- `SizeOfRawData`: This field specifies the size of section on disk.
- `Characteristics`: This field specifies the characteristics of section. Lets discuss some important ones. Other are documented here: [PE Format - Section Charactersitics](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags)
    - `IMAGE_SCN_CNT_CODE`: Its value is `0x20`, which indicates the section contains executable code.
    - `IMAGE_SCN_CNT_INITIALIZED_DATA`: Its value is `0x40` , which indicates the section contains initialized data.
    - `IMAGE_SCN_CNT_UNINITIALIZED_DATA`: Its value is `0x80` , which indicates the section contains uninitialized data.
    - `IMAGE_SCN_MEM_EXECUTE`: Its value is `0x20000000`, which indicate the section can be executed as code.
    - `IMAGE_SCN_MEM_READ`:  Its value is `0x40000000`, which indicate the section can be read.
    - `IMAGE_SCN_MEM_WRITE`: Its value is `0x80000000`, which indicate the section can be written to.


Lets view the Section Header in PE-Bear.

![PE Bear](/images/2024-08-22-File_Format-PE/2.png)

**Note:** 

- If `VirtualSize` is greater than `SizeOfRawData` , then it means that the binary will allocate more memory space than its data on disk. This is common with malware samples that are packed, where it the difference between them is very high.
- Also the packed malware samples may have modified or added section name  based on the packer like UPX, VMP, or even random generated names.
- Below is the example of ‘calc.exe’ packed with UPX packer.

![PE Bear](/images/2024-08-22-File_Format-PE/3.png)

<br>

---

## Section

![PE Illustration](/images/2024-08-22-File_Format-PE/4.png)

After the Section Header are the Sections. Sections are the container of certain data with specific purpose. The sections are named according to their purposes which are documented here: [PE Format - Sections](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#special-sections) 

Lets understand some of the common sections:

- .text - This section contains executable code which will be never page out of memory to disk.
- .data - This section contains global read/write initialized data.
- .rdata – This section contains read-only initialized data.
- .bss - This section contains special global data which are not initialized.  This will be 0 in size in disk but some size in memory. Example: Declaring int a; and its value is later assigned.
- .idata – This section contains import table information.
- .edata – This section contains export table information.
- .pdata – This section contains 64-bit exception handling data.
- .rsrc - This section contains resources (icons to embedded binaries) organized like of filesystem. **Note:** Malware often hide their next stager payload under this section. You can dump the payload using tools like Resource Hacker.
- .reloc – This section contains relocation information.
- .tls - This section provide TLS (Thread Local Storage) for every executing thread of program to store thread-specific data.

<br>

---