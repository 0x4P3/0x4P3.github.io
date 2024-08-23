---
layout:	post
title:  "(III) PE Header: NT Header"
date:   2024-08-23 11:11:11 +0200
categories: [Portable Executable (PE)]
tags: [PE]
---


## NT Header

![PE Illustration](/images/2024-08-23-File_Format-PE-Header-II/1.png)

Following the Rich Header is the NT Header. The NT Header structure is defined for both 32-bit and 64-bit architecture. This part of the header is what helps the OS loader to determine whether the PE file is 32-bit or 64-bit.

- 32-bit
    
    ```c
    typedef struct _IMAGE_NT_HEADERS {
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    } IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
    ```
    
- 64-bit
    
    ```c
    typedef struct _IMAGE_NT_HEADERS64 {
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    } IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
    ```

Lets now understand those components of NT Header.

<br>

### Signature

![PE Illustration](/images/2024-08-23-File_Format-PE-Header-II/2.png)

The Signature is a 4 byte value that points to the 0x50450000 or PE\0\0. This can also be seen in the screenshot below from PE-Bear. 

![PE-Bear](/images/2024-08-23-File_Format-PE-Header-II/3.png)

This value helps OS loader to determine that the file is a PE file.

<br>

### File Header

![PE Illustration](/images/2024-08-23-File_Format-PE-Header-II/4.png)

Lets now focus on the important ones:

- `Machine`: This field value specifies the type of CPU architecture that PE file can execute on.
    - Some important values are `0x8664` for `IMAGE_FILE_MACHINE_AMD64` CPU architecture and `0x14c` for `IMAGE_FILE_MACHINE_I386` CPU architecture .
    - All the values for CPU architecture are documented here: [PE Format - Machine Types](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types)
- `NumberOfSections`: This field value specifies the number of section present in the PE file. We will cover sections later.
- `TimeDateStamp`: This field value specifies the linked timestamp of the binary in EPOC format.
- `SizeOfOptionalHeader`: This field value specifies the size of Optional Header. This is because the Optional Header does not have a fixed size. The Optional Header will be covered in next section.
- `Characteristics`: This field contain flag that indicates the attribute of PE file. Following one are important characteristics.
    - `IMAGE_FILE_EXECUTABLE_IMAGE`: Its value is `0x2`  which indicates that the PE file is an executable.
    - `IMAGE_FILE_DLL`: Its value is `2000` which indicates that the PE file is a DLL.
    - `IMAGE_FILE_LARGE_ADDRESS_ AWARE`: Its value is `20` which indicates that the PE file can handle large address space so that 32-bit binary when executed on 64-bit machine can access up to 4 GB virtual address space instead of usual 2 GB.
    - All other characteristics are documented here: [PE Format - Characteristics](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics)

Lets check the File Header in PE-Bear.

![PE-Bear](/images/2024-08-23-File_Format-PE-Header-II/5.png)

- The `Machine` value is `0x8664`, which is translated by PE-Bear as AMD64.
- The `NumberOfSections` value is ***6***, which are .text, .rdata, .data, .pdata, .rsrc and .reloc.
- The `TimeDateStamp` value is ***0x340C410***, which is in EPOC format. This value is also translated by PE-Bear into UTC format.
- The `SizeOfOptionalHeader` value is ***240***.
- The `Characteristics` value is `0x22`, i.e., `0x2` for `IMAGE_FILE_EXECUTABLE_IMAGE` and `0x20` for `IMAGE_FILE_LARGE_ADDRESS_ AWARE` , which is also translated by PE-Bear.

<br>

### Optional Header

![PE Illustration](/images/2024-08-23-File_Format-PE-Header-II/6.png)

The Optional Header is the one that helps OS loader to determine whether the PE file is 32-bit or 64-bit. So, the Optional Header is defined for both 32-bit and 64-bit architecture. 

- 32-bit
    
    ```c
    typedef struct _IMAGE_OPTIONAL_HEADER {
        WORD    Magic;
        BYTE    MajorLinkerVersion;
        BYTE    MinorLinkerVersion;
        DWORD   SizeOfCode;
        DWORD   SizeOfInitializedData;
        DWORD   SizeOfUninitializedData;
        DWORD   AddressOfEntryPoint;
        DWORD   BaseOfCode;
        DWORD   BaseOfData;
        DWORD   ImageBase;
        DWORD   SectionAlignment;
        DWORD   FileAlignment;
        WORD    MajorOperatingSystemVersion;
        WORD    MinorOperatingSystemVersion;
        WORD    MajorImageVersion;
        WORD    MinorImageVersion;
        WORD    MajorSubsystemVersion;
        WORD    MinorSubsystemVersion;
        DWORD   Win32VersionValue;
        DWORD   SizeOfImage;
        DWORD   SizeOfHeaders;
        DWORD   CheckSum;
        WORD    Subsystem;
        WORD    DllCharacteristics;
        DWORD   SizeOfStackReserve;
        DWORD   SizeOfStackCommit;
        DWORD   SizeOfHeapReserve;
        DWORD   SizeOfHeapCommit;
        DWORD   LoaderFlags;
        DWORD   NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
    ```
    
- 64-bit
    
    ```c
    typedef struct _IMAGE_OPTIONAL_HEADER64 {
        WORD        Magic;
        BYTE        MajorLinkerVersion;
        BYTE        MinorLinkerVersion;
        DWORD       SizeOfCode;
        DWORD       SizeOfInitializedData;
        DWORD       SizeOfUninitializedData;
        DWORD       AddressOfEntryPoint;
        DWORD       BaseOfCode;
        ULONGLONG   ImageBase;
        DWORD       SectionAlignment;
        DWORD       FileAlignment;
        WORD        MajorOperatingSystemVersion;
        WORD        MinorOperatingSystemVersion;
        WORD        MajorImageVersion;
        WORD        MinorImageVersion;
        WORD        MajorSubsystemVersion;
        WORD        MinorSubsystemVersion;
        DWORD       Win32VersionValue;
        DWORD       SizeOfImage;
        DWORD       SizeOfHeaders;
        DWORD       CheckSum;
        WORD        Subsystem;
        WORD        DllCharacteristics;
        ULONGLONG   SizeOfStackReserve;
        ULONGLONG   SizeOfStackCommit;
        ULONGLONG   SizeOfHeapReserve;
        ULONGLONG   SizeOfHeapCommit;
        DWORD       LoaderFlags;
        DWORD       NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
    ```

Lets now focus on the important ones: