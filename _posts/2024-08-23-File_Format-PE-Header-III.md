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

<br>

---

### Data Directory - Export Table

Soon

<br>

---