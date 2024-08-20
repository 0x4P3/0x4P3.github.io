---
layout:	post
title:  "Baby RE"
date:   2024-08-11 01:11:11 +0200
categories: [HTB Track - Reversing]
tags: [HTB]
---


The challenge binary is a 64-bit ELF file format as can be seen below. Also this file is not stripped so the debugging symbols will be present in this file. This will make the analysis easier.

```bash
$ file baby
baby: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=25adc53b89f781335a27bf1b81f5c4cb74581022, for GNU/Linux 3.2.0, not stripped
```

On executing the challenge binary, it asks for key Here, ‘ape’ was entered which failed obviously. We need to reverse it to retrieve the correct key.

```bash
$ ./baby 
Insert key: 
ape
Try again later.
```

<br>

## Ghidra

First thing I usually like to do is load the binary in Ghidra and jump to its main function.

![Ghidra](/images/2024-08-11-HTB_Reversing_Baby_RE/1.png)

-   It can be seen that the userInput is compared to ‘abcde122313’ with _**strcmp**_, which seems to be the key.
-   If the userInput matches, it seems to print the flag. Otherwise, it prints ‘Try again later’.

Lets confirm the key.

```bash
$ ./baby 
Insert key: 
abcde122313
HTB{B4BY_R3V_TH4TS_EZ}
```

<br>

## GDB


Lets try this with GDB.

```bash
$ gdb -q baby
```

Before doing anything, lets set the syntax to Intel because I am comfortable with it. The default one is AT&T.

```bash
(gdb) set disassembly-flavor intel
```

We know there is main function so lets add breakpoint on it and run the program.

```bash
(gdb) b main
Breakpoint 1 at 0x1159

(gdb) r
Starting program: /home/remnux/HTB/RE/baby 
Breakpoint 1, 0x0000555555555159 in main ()
```

The program has hit the breakpoint on main. Lets now disassemble the program.

```bash
(gdb) disass 
Dump of assembler code for function main:
   0x0000555555555155 <+0>:	push   rbp
   0x0000555555555156 <+1>:	mov    rbp,rsp
=> 0x0000555555555159 <+4>:	sub    rsp,0x40
   0x000055555555515d <+8>:	lea    rax,[rip+0xea4]        # 0x555555556008
   0x0000555555555164 <+15>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000555555555168 <+19>:	lea    rdi,[rip+0xed7]        # 0x555555556046
   0x000055555555516f <+26>:	call   0x555555555030 <puts@plt>
   0x0000555555555174 <+31>:	mov    rdx,QWORD PTR [rip+0x2ec5]        # 0x555555558040 <stdin@@GLIBC_2.2.5>
   0x000055555555517b <+38>:	lea    rax,[rbp-0x20]
   0x000055555555517f <+42>:	mov    esi,0x14
   0x0000555555555184 <+47>:	mov    rdi,rax
   0x0000555555555187 <+50>:	call   0x555555555040 <fgets@plt>
   0x000055555555518c <+55>:	lea    rax,[rbp-0x20]
   0x0000555555555190 <+59>:	lea    rsi,[rip+0xebc]        # 0x555555556053
   0x0000555555555197 <+66>:	mov    rdi,rax
   0x000055555555519a <+69>:	call   0x555555555050 <strcmp@plt>
   0x000055555555519f <+74>:	test   eax,eax
   0x00005555555551a1 <+76>:	jne    0x5555555551da <main+133>
   0x00005555555551a3 <+78>:	movabs rax,0x594234427b425448
   0x00005555555551ad <+88>:	movabs rdx,0x3448545f5633525f
   0x00005555555551b7 <+98>:	mov    QWORD PTR [rbp-0x40],rax
   0x00005555555551bb <+102>:	mov    QWORD PTR [rbp-0x38],rdx
   0x00005555555551bf <+106>:	mov    DWORD PTR [rbp-0x30],0x455f5354
   0x00005555555551c6 <+113>:	mov    WORD PTR [rbp-0x2c],0x7d5a
   0x00005555555551cc <+119>:	lea    rax,[rbp-0x40]
   0x00005555555551d0 <+123>:	mov    rdi,rax
   0x00005555555551d3 <+126>:	call   0x555555555030 <puts@plt>
   0x00005555555551d8 <+131>:	jmp    0x5555555551e6 <main+145>
   0x00005555555551da <+133>:	lea    rdi,[rip+0xe7f]        # 0x555555556060
   0x00005555555551e1 <+140>:	call   0x555555555030 <puts@plt>
   0x00005555555551e6 <+145>:	mov    eax,0x0
   0x00005555555551eb <+150>:	leave  
   0x00005555555551ec <+151>:	ret    
End of assembler dump.
```

We can see that there is call to _**strcmp**_ at offset `0x000055555555519a`.

The strcmp command will compare value of RSI with RDI register. Here,

-   The RDI register holds the user provided input value.
-   The RSI register holds the key.

So we can jump to offset of _**strcmp**_ before it compares. Also ‘ape’ was entered as user input.

```bash
(gdb) until *0x000055555555519a
Insert key: 
ape

0x000055555555519a in main ()
```

Now we can check out the memory value of RSI register to get the key.

```bash
(gdb) x/s $rsi
0x555555556053:	"abcde122313\\n"
```

Lets confirm the key.

```bash
$ ./baby                       
Insert key: 
abcde122313
HTB{B4BY_R3V_TH4TS_EZ}
```

<br>

## Ltrace

An easy option is using ltrace as can be seen below.

```bash
$ ltrace ./baby

puts("Insert key: "Insert key: 
)                                                                                                              = 13
fgets(ape
"ape\\n", 20, 0x7f72aa864980)                                                                                                = 0x7ffd725ed440
strcmp("ape\\n", "abcde122313\\n")                                                                                                  = 14
puts("Try again later."Try again later.
)                                                                                                          = 17
+++ exited (status 0) +++
```
