---
layout:	post
title:  "(IV) PE Header: NT Header - Optional Header - Data Directory"
date:   2024-08-22 09:11:11 +0200
categories: [Portable Executable (PE)]
tags: [PE]
---

---

The previous part of this blog series: [PE Header: NT Header](https://venuschhantel.com.np/posts/File_Format-PE-Header-II/)

<br>

---

## Data Directory

In the previous blog of this series, the Data Directory were only mentioned as last member of Optional Header. In this part, we will dive more into Data Directory. 

Data directory are data array that store pointers from all other data structures that are located within one of the section of PE file. Those data structures are listed below.

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

All of the above listed data directories have the same structure defined as:

```c
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

The `VirtualAddress` specifies the RVA of start of the Data Directory and the `Size` specifies size of that Data Directory.

Lets now cover some important Data Directory.

<br>

---

### Data Directory - Import Directory

The Import Data Directory points to another structure:

```c
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;     // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;  // RVA to original unbound IAT (INT) (PIMAGE_THUNK_DATA)
    };
    DWORD   TimeDateStamp;           // 0 if not bound,
                                     // -1 if bound, and real date\time stamp in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 

    DWORD   ForwarderChain;       
    DWORD   Name;
    DWORD   FirstThunk;              // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
```

Lets understand the important components:

- `Name`: This field specifies the RVA that points to name of module (Example: kernel32.dll, ntdll.dll, etc.) from which imports are taken from.
- `TimeDateStamp`: This field:
    - If bound, value is 0.
    - If not bound, then value is -1 with data/time stamp in `IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT`. We will cover bound import in next section.
- `ForwarderChain`:  This field specifies the index of first forwarder chain reference for DLL forwarding (DLL forwards its exported function to another DLL).
- `OriginalFirstThunk`: This field specifies the RVA of INT (Import Name Table), aka ILT (Import Lookup Table).
- `FirstThunk`: This field specifies the RVA of IAT (Import Address Table).

Both `OriginalFirstThunk` and `FirstThunk` points to another data structure called `_IMAGE_THUNK_DATA`, which is described below.

```c
typedef struct _IMAGE_THUNK_DATA {
    union {
        DWORD ForwarderString;     
        DWORD Function;             
        DWORD Ordinal;
        PIMAGE_IMPORT_BY_NAME AddressOfData;  
    } u1;
} IMAGE_THUNK_DATA;
```

- `ForwarderString`:  This field specifies the RVA pointing to name of DLL to which the import is forwarded to.
- `Function`: After resolution of functions, this field holds address of imported function. We will discuss this more later.
- `Ordinal`: This field specifies the ordinal. Here, ordinal is index of function. **Note:** If a function is exported by ordinal, then it must be imported by ordinal.

The `PIMAGE_IMPORT_BY_NAME` points to another data structure called `_IMAGE_IMPORT_BY_NAME`, which is described below.

```c
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    BYTE    Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```

- `Hint`: This field specifies the ordinal of imported function.
- `Name`: This field specifies the name of the import function. The `Name` follows the `Hint`
    - Example: 0x14B, NtQuerySysInfo
    - Here, 0x14B is ordinal and NtQuerySysInfo is name.
    - When lookup import function by `Name`, it looks for index 0x14B in export of module it want to import from and match the `Name`  till success.

**NOTE:**

Initially when PE file is on disk, the `_IMAGE_THUNK_DATA`  structure points to `_IMAGE_IMPORT_BY_NAME`  structure, i.e. `u1.AddressOfData`. This is interpreted as INT (Import Name Table).

Once OS resolve each of the import functions of the PE file, the  `_IMAGE_THUNK_DATA` structure is overwritten with virtual address of start of imported function, i.e. `u1.Function`. This is interpreted as IAT (Import Address Table).

On disk, both OriginalFirstThunk and FirstThunk  point to INT, as can be seen in illustration below. 

![PE Import Illustration](/images/2024-08-23-File_Format-PE-Header-III/1.png)

Only after execution and resolution of import function by OS loader, FirstThunk will point to IAT, as can be seen in illustration below..

![PE Import Illustration](/images/2024-08-23-File_Format-PE-Header-III/2.png)

Lets view Imports in PE-Bear.

![PE-Bear](/images/2024-08-23-File_Format-PE-Header-III/3.png)

<br>

---

### Data Directory - Bound Import Directory

Bound Imports is speed optimization technique where address of import function for specific version of DLL are assumed and resolved at link time and place in IAT (Import Address Table). 

The Bound Import Data Directory points to another structure:

```c
typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
    DWORD   TimeDateStamp;
    WORD    OffsetModuleName;
    WORD    NumberOfModuleForwarderRefs;
// Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
} IMAGE_BOUND_IMPORT_DESCRIPTOR,  *PIMAGE_BOUND_IMPORT_DESCRIPTOR;
```

But note that ASLR (Address Space Layout Randomization) will fix the IAT entries making the bound import useless.

<br>

---

### Data Directory - Delay Load Import Directory

Soon

<br>

---

The next part of the blog series: [PE Header: Section Header & PE Sections](https://venuschhantel.com.np/posts/File_Format-PE-Header-Section/)

<br>

---