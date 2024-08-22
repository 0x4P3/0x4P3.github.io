---
layout:	post
title:  "Exatlon"
date:   2024-08-11 09:11:11 +0200
categories: [HTB Track, Intro to Reversing]
tags: [HTB]
---

The challenge binary is a 64-bit ELF file format as can be seen below. 

```bash
$ file exatlon_v1 
exatlon_v1: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, no section header
```

Also note that the output said it has not section header. This might indicate its packed. 

The challenge binary was loaded in ‘Detect It Easily’, where it was found to be packed with UPX.

![Detect It Easily](/images/2024-08-11-HTB_Reversing_Exatlon/1.png)

The challenge binary was then unpacked and saved as ‘unpacked_exatlon_v1’.

```bash
$ upx -d exatlon_v1 -o unpacked_exatlon_v1

                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   2202568 <-    709524   32.21%   linux/amd64   unpacked_exatlon_v1

Unpacked 1 file.
```

Then the unpacked binary was executed, which ask for password. Here, ‘ape’ was entered but failed obviously. We need to reverse it to retrieve the correct password. 

```bash
$ ./exatlon_v1 

███████╗██╗  ██╗ █████╗ ████████╗██╗      ██████╗ ███╗   ██╗       ██╗   ██╗ ██╗
██╔════╝╚██╗██╔╝██╔══██╗╚══██╔══╝██║     ██╔═══██╗████╗  ██║       ██║   ██║███║
█████╗   ╚███╔╝ ███████║   ██║   ██║     ██║   ██║██╔██╗ ██║       ██║   ██║╚██║
██╔══╝   ██╔██╗ ██╔══██║   ██║   ██║     ██║   ██║██║╚██╗██║       ╚██╗ ██╔╝ ██║
███████╗██╔╝ ██╗██║  ██║   ██║   ███████╗╚██████╔╝██║ ╚████║███████╗╚████╔╝  ██║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═══╝   ╚═╝

[+] Enter Exatlon Password  : ape
[-] ;(
```

First thing I usually like to do is load the binary in Ghidra and analyze from main.

![Ghidra](/images/2024-08-11-HTB_Reversing_Exatlon/2.png)

It can be seen that it ask for userInput. The userInput is then processed in exatlon() function to get processedInput. 

The processedInput is then matched with a series of string `1152 1344 1056 1968 1728 816 1648 784 1584 816 1728 1520 1840 1664 784  1632 1856 1520 1728 816 1632 1856 1520 784 1760 1840 1824 816 1584 1856  784 1776 1760 528 528 2000`, which should be the obfuscated flag. 

- If it matches, then it prints `[+] Looks Good ^_^`.
- If it does not match, then it prints `[-] ;(`.

When checking under the exatlon() function, it was found that the userInput was left shifted by 4 to get the processedInput as can be seen below.

![Ghidra](/images/2024-08-11-HTB_Reversing_Exatlon/3.png)

This mean that the string `1152 1344 1056 1968 1728 816 1648 784 1584 816 1728 1520 1840 1664 784  1632 1856 1520 1728 816 1632 1856 1520 784 1760 1840 1824 816 1584 1856  784 1776 1760 528 528 2000` that will be matched is left shifted by 4 of flag. So, to get the flag we need to right sift by 4.

I wrote a simple python script to achieve this.

```bash
shifted_flag = [1152, 1344, 1056, 1968, 1728, 816, 1648, 784, 1584, 816, 1728, 1520, 1840, 1664, 784, 1632, 1856, 1520, 1728, 816, 1632, 1856, 1520, 784, 1760, 1840, 1824, 816, 1584, 1856, 784, 1776, 1760, 528, 528, 2000]

flag = ''.join(chr(x >> 4) for x in shifted_flag)

print(flag)
```

![Ghidra](/images/2024-08-11-HTB_Reversing_Exatlon/4.png)

```bash
HTB{l3g1c3l_sh1ft_l3ft_1nsr3ct1on!!}
```