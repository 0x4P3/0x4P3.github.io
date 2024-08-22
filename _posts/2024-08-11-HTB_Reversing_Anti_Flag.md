---
layout:	post
title:  "Anti Flag"
date:   2024-08-11 05:11:11 +0200
categories: [HTB Track, Intro to Reversing]
tags: [HTB]
---

The challenge binary is a 64-bit ELF file format as can be seen below. Also this file is stripped so the debugging symbols will not be present in this file. This will make the analysis a bit harder.

```bash
$ file anti_flag 
anti_flag: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b8de97bc12c627606510140e43fc13e2efffcee5, for GNU/Linux 3.2.0, stripped
```

On executing the challenge binary, it prints ‘No flag for you :(’. 

```bash
$ ./anti_flag 
No flag for you :(
```

First thing I usually like to do is load the binary in Ghidra. Since this binary is stripped, it might be harder to locate main. The main code is located at `FUN_00101486`.

![Ghidra](/images/2024-08-11-HTB_Reversing_Anti_Flag/1.png)

- It can be seen that there is call to ***ptrace***, which will checks if the process is being debugged.
- If not found being debugged, it print ‘No flag for you :(’.
- If found being debugged, it should print ‘Well done!!’.

Lets verify. 

```bash
$ gdb -q ./anti_flag

Reading symbols from ./anti_flag...
(No debugging symbols found in ./anti_flag)

(gdb) r
Starting program: /home/remnux/HTB/RE/anti_flag 
Well done!!
```

Lets find the execution flow to retrieve the flag.

![Ghidra](/images/2024-08-11-HTB_Reversing_Anti_Flag/2.png)

- The program checks if being debugged at offset `0x001014f0` with ***CMP*** instruction after the call to ***ptrace***.
- If found to be debugged, it will not take the jump and prints “Well done!”, then exits.
- If not being debugged, it will take jump to offset `0x00101509`. There is yet another ***CMP*** instruction, where it is comparing a local variable with 0x539. The local variable is the '2asdf-012=14’. So, the program is bound to fail this check so it will not take the jump and prints ‘No flag for you :(’, then exits.
- To retrieve the flag, we need to patch this program.
    - An easy way is to patch the ***JZ***  instruction at offset `0x00101510` to *JNZ*  instruction.

The program was patched by replacing the ***JZ***  instruction at offset `0x00101510` to *JNZ*  instruction as can be seen below. After patching the program, the binary was exported.

![Ghidra](/images/2024-08-11-HTB_Reversing_Anti_Flag/3.png)

Lets now check the patched binary output.

```bash
$ ./patched_anti_flag
HTB{y0u_trac3_m3_g00d!!!}
```