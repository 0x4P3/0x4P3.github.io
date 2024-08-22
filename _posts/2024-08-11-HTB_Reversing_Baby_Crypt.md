---
layout:	post
title:  "Baby  Crypt"
date:   2024-08-11 03:11:11 +0200
categories: [HTB Track, Intro to Reversing]
tags: [HTB]
---


The challenge binary is a 64-bit ELF file format as can be seen below. Also this file is not stripped so the debugging symbols will be present in this file. This will make the analysis easier.

```bash
$ file baby_crypt 
baby_crypt: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=24af7e68eab982022ea63c1828813c3bfa671b51, for GNU/Linux 3.2.0, not stripped
```

On executing the challenge binary, it asks for key Here, ‘ape’ was entered which failed obviously. We need to reverse it to retrieve the correct key.

```bash
$ ./baby_crypt 
Give me the key and I'll give you the flag: ape
^Pm8"d#egesvI"kI(&np`7=
```

First thing I usually like to do is load the binary in Ghidra and jump to its main function.

![Ghidra](/images/2024-08-11-HTB_Reversing_Baby_Crypt/1.png)

- It can be seen that only the first 3 letters of userInput is used when performing XOR. So the key should be of 3 letters.

The XOR operation works as: A ^ B = C, then A ^ C = B or B ^ C = A

Example: 1 ^ 1 = 0, then 1 ^ 0 = 1

Using the above logic: 

[SomeValue] ^ [InputKey] = [Flag], then [SomeValue] ^ [Flag] = [InputKey]

We know the flag format is HTB{…}. If we enter the ‘HTB’ as input, we should be able to receive the key after the XOR operation since the key is also 3 letters.

```bash
$ ./baby_crypt 
Give me the key and I'll give you the flag: HTB
w0wDM;L;@LWQ`L`
               GTG
```

We received the key ‘w0w’. Using the key, we can retrieve the flag. 

```bash
$ ./baby_crypt 
Give me the key and I'll give you the flag: w0w
HTB{x0r_1s_us3d_by_h4x0r!}
```