---
layout:	post
title:  "(III) PE Header: NT Header"
date:   2024-08-22 07:11:11 +0200
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

Lets now focus on the important ones. Other are documented here: [PE Format - Optional Header](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only)

- `Magic` :  This field value specified whether the PE file is 32-bit/64-bit. So with this value, the OS loader determines if the PE file is 32-bit/64-bit.
    - For 32-bit (PE32), the value is `0x10B` .
    - For 64-bit (PE32+), the value is `0x20B`.
- `AddressOfEntryPoint`:  This field value specifies the RVA (Relative Virtual Address) of entry point. The RVA are relative to starting address.
- `ImageBase`:  This field value specifies the preferred virtual address of first byte of binary when loaded in memory.
    - Nowadays, security mechanism called ASLR (Address Space Layout Randomization) is enabled, which randomizes the address where binary are loaded into memory. This renders this field useless. Each time, the binary are loaded at different address.
- `SubSystem`:  This field value specifies the subsystem required to run the binary. When triaging a malware, we can know if the malware will have GUI or CLI and prepare accordingly.
    - For `IMAGE_SUBSYSTEM_WINDOWS_GUI`, its value is `0x2`.
    - For `IMAGE_SUBSYSTEM_WINDOWS_CUI`, its value is `0x3`.
    - Other subsystem are documented here: [PE Format - Subsystem](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#windows-subsystem)
- `DLLCharacteristics`: This field values specifies the characteristics of the PE file. Lets focus some important ones:
    - `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`: Its value is `0x40`, which enables ASLR that randomizes address where binary loads.
        - During analyzing malware, we can disable ASLR feature to make the analysis easier. We can disabled the ASLR using CFF Explorer.
            - NtHeaders > OptionalHeader > DllCharacteristics > Uncheck ‘DLL can move’
            
            ![image.png](/images/2024-08-23-File_Format-PE-Header-II/7.png)
            
    - `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY`: Its value is `0x80`, which checks if digitally signed hash matched at load time.
    - `IMAGE_DLLCHARACTERISTICS_NX_COMPAT`: Its value is `0x100`, which enables DEP that make sure that code are not executed from non-executable memory locations.
    - Other DLLCharacteristics are documented here: [PE Format - DllCharacteristics](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#dll-characteristics)
- `DataDirectory` : This field value store array that store pointers from all other data structures, which are:
    
    ```c
    #define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
    #define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
    #define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
    #define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
    #define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security/Certificate Directory
    #define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
    #define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
    #define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data (reserved 0)
    #define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
    #define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
    #define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
    #define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
    #define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
    #define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
    #define IMAGE_DIRECTORY_ENTRY_CLR_DESCRIPTOR 14   // CLR Runtime descriptor
    //Reserved must be 0                         15
    ```
    
    - Important data structures will be covered in next blog.
