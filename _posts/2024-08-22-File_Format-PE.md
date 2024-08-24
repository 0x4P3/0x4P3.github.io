---
layout:	post
title:  "(I) PE: Overview"
date:   2024-08-22 05:11:01 +0200
categories: [Portable Executable (PE)]
tags: [PE]
---

---

## Getting Started

A deep understanding of the PE file format is fundamental from Windows malware analyst perspective, as it serves as the foundation for analyzing Windows binaries. In this blog series, I will provide an in-depth breakdown of the PE file format, along with some practical tips to help in your malware analysis.

If you want to follow along, the tools that I will be using on this blog series are:

- PE-bear
- CyberChef

Lets now get our hand dirty.

<div style="text-align: center;">
  <img src="https://media.giphy.com/media/1TzKVQwH820wM/giphy.gif" alt="GIF" style="max-width: 100%; height: auto;">
</div>

<br>

---

## PE Overview

The PE stands for Portable Executable, which is a standard file format for most Windows binaries, including:

- Executables (.exe)
- Dynamic Link Libraries (.dll)
- Screen Saver (.scr)
- Control Panel (.cpl)
- System File (.sys)
- Kernel Driver (.drv)
- Kernel Modules (.srv)

The PE file format is derived from Common Object File Format (COFF). And, the PE file format specifies the necessary information required by OS loader to load the binary in memory and execute it.

<br>

---

## PE Structure Overview

The PE file format is organized as linear steam of data consisting of a header followed by many sections. The PE file format is illustrated in the image below.

![PE Illustration](/images/2024-08-22-File_Format-PE/PE.jpg)

This above structure can be seen following in PE-bear tool. Each of those PE structure will be covered in the next section.

![PE-bear](/images/2024-08-22-File_Format-PE/PE-bear.png)

<br>

---

## PE Structures 

[PE Header: MS DOS Header, MS DOS Stub & Rich Header](https://venuschhantel.com.np/posts/File_Format-PE-Header-I/)

[PE Header: NT Header](https://venuschhantel.com.np/posts/File_Format-PE-Header-II/)

<br>

---

## References

[PE Format - Win32 apps - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) 

[2013 Day1P1 Life of Binaries: Intro (youtube.com)](https://www.youtube.com/watch?v=ls8I__h1IYE&list=PLUFkSN0XLZ-n_Na6jwqopTt1Ki57vMIc3)  

[A dive into the PE file format - Introduction - 0xRick’s Blog](https://0xrick.github.io/win-internals/pe1/)  

[Introduction to the PE file format - Cyberdough (skr1x.github.io)](https://skr1x.github.io/portable-executable-format/#pe-parser)  

[Portable Executable File Format (kowalczyk.info)](https://blog.kowalczyk.info/articles/pefileformat.html)

<br>

---