---
layout:	post
title:  "You Cant C Me"
date:   2024-08-11 02:11:11 +0200
categories: [HTB Track, Intro to Reversing]
tags: [HTB]
---


The challenge binary is a 64-bit ELF file format as can be seen below. Also this file is stripped so the debugging symbols will not be present in this file. This will make the analysis a bit harder.

```bash
$ file auth 
auth: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped
```

On executing the challenge binary, it prints ‘Welcome’ and asks for some input. Here, ‘ape’ was entered but failed obviously. We need to reverse it to retrieve the correct key.

```bash
$ ./auth 
Welcome!
ape
I said, you can't c me!
```

First thing I usually like to do is load the binary in Ghidra. Since this binary is stripped, it might be harder to locate main. The main function is located at `FUN_00401160`.

![Ghidra](/images/2024-08-11-HTB_Reversing_You_Cant_C_Me/1.png)


-   It can be seen that the userInput is compared to a generatedKey value with _**strcmp**_, which will be generated at run-time.
-   If the userInput matches, it seems to print the flag. Otherwise, it prints ‘I said, you can’t c me!’.

Lets use GDB to retrieve the generatedKey value.

```bash
$ gdb -q auth
```

Before doing anything, lets set the syntax to Intel because I am comfortable with it. The default one is AT&T.

```bash
(gdb) set disassembly-flavor intel
```

Since the binary is stripped the debugging symbols will not be present. Lets check the non-debugging symbols.

```bash
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x0000000000401030  printf@plt
0x0000000000401040  fgets@plt
0x0000000000401050  strcmp@plt
0x0000000000401060  malloc@plt
```

We know from Ghidra that the user input value will be compared with generatedKey value with _**strcmp**_. On above output, the call to strcmp is at `0x0000000000401050`. So lets add breakpoint on that address and run the program. Again, ‘ape’ was entered as user input.

```bash
(gdb) b *0x0000000000401050
Breakpoint 1 at 0x401050

(gdb) r
Starting program: /home/remnux/HTB/RE/auth 
Welcome!
ape

Breakpoint 1, 0x0000000000401050 in strcmp@plt ()
```

The program has hit breakpoint at _**strcmp**_. Lets now check the memory value of RDI and RSI registry to get the generatedKey.

```bash
gdb) x/s $rsi
0x4056b0:	"ape\\n"

(gdb) x/s $rdi
0x7fffffffdfb0:	"wh00ps!_y0u_d1d_c_m3"
```

We have the generatedKey and we can get the flag.

```bash
$ ./auth 
Welcome!
wh00ps!_y0u_d1d_c_m3
HTB{wh00ps!_y0u_d1d_c_m3}
```

<br>

Alternatively, using ltrace.

```bash
ltrace ./auth

printf("Welcome!\\n"Welcome!
)                                                                                                              = 9
malloc(21)                                                                                                                        = 0x83b6b0
fgets(ape
"ape\\n", 21, 0x7f57637e6980)                                                                                                = 0x83b6b0
strcmp("wh00ps!_y0u_d1d_c_m3", "ape\\n")                                                                                           = 22
printf("I said, you can't c me!\\n"I said, you can't c me!
)                                                                                               = 24
+++ exited (status 0) +++
```
