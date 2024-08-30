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

Imports are functions that are provided by other DLLs (Dynamic-Link Libraries), which a PE file, such as an executable, incorporates to perform specific tasks. The Import Data Directory is located under `.idata` section.

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
- `OriginalFirstThunk`: This field specifies the RVA of INT (Import Name Table), also known as ILT (Import Lookup Table).
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

Before understanding Delay Load Import, its first understand about some linking: 

- Static Linking (also known as Implicit Linking) is when application is linked to a DLL at compile time. So the linker creates a dependency on the DLL and OS loader loads those DLL when application starts.
- Dynamic Linking (also known as Explicit Linking) is when application loads the DLL at runtime, only when needed, using functions like `LoadLibrary` and `GetProcAddress`.
- Delay-Load Import is when application is linked to the DLL at compile time, but loads DLL at runtime only when actually needed. The loading of DLL is delayed until needed by application.

The Delay-Load Import Directory points to another structure:

```c
typedef struct _IMAGE_DELAY_IMPORT_DESCRIPTOR {
DWORD           grAttrs;        // attributes
RVA             rvaDLLName;     // RVA to dll name
RVA             rvaHmod;        // RVA of module handle
RVA             rvaIAT;         // RVA of the IAT
RVA             rvaINT;         // RVA of the INT
RVA             rvaBoundIAT;    // RVA of the optional bound IAT
RVA             rvaUnloadIAT;   // RVA of optional copy of original IAT
DWORD           dwTimeStamp;    // 0 if not bound,
                                // O.W. date/time stamp of DLL bound to (Old BIND)
} ImgDelayDescr, * PImgDelayDescr;
```

Lets understand the important components:

- `rvaDLLName`: This field specifies which DLL to delay load import.
- `rvaIAT`: This field specifies the IAT (Import Address Table) for delay-load functions only.
    - Initially, it holds virtual address of stub code (delay load helper).
    - When delay load import function is called for first time, the stub code loads the DLL that contain the function to be imported and resolves the address of import function and save the import function address.
    - Next time when delay load import function is called, it directly uses the import function address.

Below is the example from [Open Security Training](https://www.opensecuritytraining.info/LifeOfBinaries.html).

- When the delay load import function `DrawThemeBackground` is called for first time. The stub code resolves the address of function and save the import function address.
    
    ![OST-DelayLoadImport](/images/2024-08-23-File_Format-PE-Header-III/4.png)

    ![OST-DelayLoadImport](/images/2024-08-23-File_Format-PE-Header-III/5.png)

    ![OST-DelayLoadImport](/images/2024-08-23-File_Format-PE-Header-III/6.png)

- Next time when delay load import function `DrawThemeBackground` is called, it directly uses the import function address.
    
    ![OST-DelayLoadImport](/images/2024-08-23-File_Format-PE-Header-III/7.png)

<br>

---

### Data Directory - Export Directory

Exports are functions that a DLL makes available for other PE files, such as executables, to use.

Functions can be exported via:

- Name
- Ordinal (Index)

The Export Data Directory is located under `.edata` section.

The Export Data Directory points to another structure:

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

Lets understand some important ones:

- `NumberOfFunctions` and `NumbersOfNames` : These both value specifies the number of exporting functions. But note that this both value may be different if exporting by ordinal.
- `AddressOfFunction`: This field specifies the RVA which points to beginning of array which holds DWORD RVAs that points to start of exported function. This is equivalent to EAT (Export Address Table).
- `AddressOfName`: This field specifies the RVA which points to beginning of array which holds DWORD RVAs that points to strings of function name. This is equivalent to ENT (Export Name Table).
- `Base`: This field specifies the number that needs to be subtracted to get zero-indexed offset into `AddressOfFunction` offset.
    - Example: Ordinally usually starts with 1 then base is 1. But ordinal can be set to start at any according to programmer like say 37. then the base will be 37. Below is example from [Open Security Training](https://www.opensecuritytraining.info/LifeOfBinaries.html).
    
    ![PEview](/images/2024-08-23-File_Format-PE-Header-III/8.png)
    
- `AddressOfNameOrdinals`: This field specifies the RVA which points to beginning of array which holds WORD size ordinals. The entries in this array are already zero-indices into EAT to not get affected by `Base`.

When importing by name, it does binary search over strings in ENT because nowadays they are lexically sorted.

- Back in days they were not sorted lexically, so it was encouraged to ‘import by ordinal’.
- But, downside of importing by ordinal is if ordinal changes, apps break

Even when importing by name, it just find index in ENT and select the same index in `AddressOfNameOrdinals`, reads it to use as index into EAT.

Let view this by loading `C:\Windows\System32\AdvancedEmojiDS.dll` in PE-Bear.

![PE-Bear](/images/2024-08-23-File_Format-PE-Header-III/9.png)


<br>

---

### Data Directory - Base Relocation Directory

As mentioned in previous blog that there is Image Base address `IMAGE_OPTIONAL_HEADER.ImageBase` where the PE file will be loaded, which is assumed at compile time. But features like ASLR (Address Space Layout Randomization) can load the PE file in another random base address, making original one invalid. For such case, the PE file is relocated by loader using Base Relocation Table. The Base Relocation Data Directory is located under `.idata` section.

The Base Relocation Data Directory points to another structure:

```c
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
//  WORD    TypeOffset[1];
} IMAGE_BASE_RELOCATION;
```

- `VirtualAddress`: This field specifies the page-aligned virtual address that specified relocation targets will be relative to.
- `SizeOfBlock`: This field specifies the size that needs to be fixed in memory range.
- Following the `SizeOfBlock` are variable number of WORD-sized relocation targets.

Lets view this in the PE-View.

![PEview](/images/2024-08-23-File_Format-PE-Header-III/10.png)

In the image above, the `VirtualAddress` (RVA of Block) and `SizeOfBlock` (Size of Block) can be seen. And following it are the WORD-sized relocation target.

Example: Lets take `0x3000`.

- The upper 4th bit, `0x3` = `IMAGE_REL_BASED_HIGHLOW` , which specifies that the RVA for data to be relocated is `VirtualAddress` + lower 12 bits (`0x000`).

Similarly, the `0x3004` is `VirtualAddress` + lower 12 bits (`0x004`) and so on.

Summing up, if feature like ASLR is enabled, the PE file will get random Image Base address `IMAGE_OPTIONAL_HEADER.ImageBase` when loaded. Suppose `0x50000` , then the address that it fixed are `0x51001`, `0x51004`, `0x51044`, and so on.

<br>

---

### Data Directory - Resource Directory

Soon

<br>

---

The next part of the blog series: [PE Header: Section Header & PE Sections](https://venuschhantel.com.np/posts/File_Format-PE-Header-Section/)

<br>

---