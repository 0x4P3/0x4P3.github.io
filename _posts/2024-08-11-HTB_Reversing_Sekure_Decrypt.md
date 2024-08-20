---
layout:	post
title:  "Sekure Decrypt"
date:   2024-08-11 07:11:11 +0200
categories: [HTB Track - Reversing]
tags: [HTB]
---

The challenge files includes a core dump (core), an ELF binary (dec) and a source code (src.c) written in C. The dec binary might have crash because of segmentation fault and dumped the core. 

```bash
$ file *
core:  ELF 64-bit LSB core file, x86-64, version 1 (SYSV), SVR4-style, from './dec', real uid: 0, effective uid: 0, real gid: 0, effective gid: 0, execfn: './dec', platform: 'x86_64'
dec:   ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=daf03fccbc32333244dc0f36e874e27457110af1, for GNU/Linux 3.2.0, with debug_info, not stripped
src.c: C source, ASCII text
```

The content of ‘src.c’ file is below, which will read ‘flag.enc’ file content, decrypts with AES algorithm and print the decrypted content. The decrypted content might be the flag. 

```bash
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

int encrypt(void* buffer, int buffer_len, char* IV, char* key, int key_len) {
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);

  if( buffer_len % blocksize != 0 ) { 
    return 1; 
  }

  mcrypt_generic_init(td, key, key_len, IV);
  mcrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}

int decrypt(void* buffer, int buffer_len, char* IV, char* key, int key_len) {
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);

  if( buffer_len % blocksize != 0 ){ 
    return 1;
  }
  
  mcrypt_generic_init(td, key, key_len, IV);
  mdecrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}

void* read_file(char* filename, int len) {
  FILE *fp = fopen(filename, "rb");
  void* data = malloc(len);
  fread(data, 1, len, fp);
  fclose(&fp);
  return data;
}

int main(int argc, char* argv[]) // gcc src.c -o dec -lmcrypt -ggdb
{
  char* IV = "AAAAAAAAAAAAAAAA";
  char *key = getenv("KEY");
  int keysize = 16;
  char* buffer;
  int buffer_len = 16;

  void *ciphertext = read_file("flag.enc", buffer_len);
  decrypt(ciphertext, buffer_len, IV, key, keysize);
  printf("Decrypted contents: %s\n", ciphertext);

  return 0;
}
```

Looks like we need to recreate this. But we do not have the key of AES algorithm and the cipher text.

The key can be retrieved from the core dump. 

```bash
$ strings core | grep KEY
KEY=
KEY=VXISlqY>Ve6D<{#F
```

In the ‘src.c’ source code above, after reading the content of the ‘flag.enc’ file, it is allocated in memory using `malloc()`, which means it resides in the heap. To determine the location of the heap, we can use GDB for verification.

```bash
$ gdb -q ./dec
Reading symbols from ./dec...

(gdb) r
Starting program: /home/remnux/HTB/RE/Sekure Decrypt/dec 

Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7e0be85 in __GI__IO_fread (buf=0x555555559480, size=1, count=16, fp=0x0) at iofread.c:35
35	iofread.c: No such file or directory.

(gdb) info proc mapping
process 3930
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      0x555555554000     0x555555555000     0x1000        0x0 /home/remnux/HTB/RE/Sekure Decrypt/dec
      0x555555555000     0x555555556000     0x1000     0x1000 /home/remnux/HTB/RE/Sekure Decrypt/dec
      0x555555556000     0x555555557000     0x1000     0x2000 /home/remnux/HTB/RE/Sekure Decrypt/dec
      0x555555557000     0x555555558000     0x1000     0x2000 /home/remnux/HTB/RE/Sekure Decrypt/dec
      0x555555558000     0x555555559000     0x1000     0x3000 /home/remnux/HTB/RE/Sekure Decrypt/dec
      0x555555559000     0x55555557a000    0x21000        0x0 [heap]
      0x7ffff7d86000     0x7ffff7d89000     0x3000        0x0 
      0x7ffff7d89000     0x7ffff7dab000    0x22000        0x0 /usr/lib/x86_64-linux-gnu/libc-2.31.so
      0x7ffff7dab000     0x7ffff7f23000   0x178000    0x22000 /usr/lib/x86_64-linux-gnu/libc-2.31.so
      0x7ffff7f23000     0x7ffff7f71000    0x4e000   0x19a000 /usr/lib/x86_64-linux-gnu/libc-2.31.so
      0x7ffff7f71000     0x7ffff7f75000     0x4000   0x1e7000 /usr/lib/x86_64-linux-gnu/libc-2.31.so
      0x7ffff7f75000     0x7ffff7f77000     0x2000   0x1eb000 /usr/lib/x86_64-linux-gnu/libc-2.31.so
      0x7ffff7f77000     0x7ffff7f7b000     0x4000        0x0 
      0x7ffff7f7b000     0x7ffff7f81000     0x6000        0x0 /usr/lib/libmcrypt.so.4.4.8
      0x7ffff7f81000     0x7ffff7f9a000    0x19000     0x6000 /usr/lib/libmcrypt.so.4.4.8
      0x7ffff7f9a000     0x7ffff7fa7000     0xd000    0x1f000 /usr/lib/libmcrypt.so.4.4.8
      0x7ffff7fa7000     0x7ffff7fa9000     0x2000    0x2b000 /usr/lib/libmcrypt.so.4.4.8
      0x7ffff7fa9000     0x7ffff7fab000     0x2000    0x2d000 /usr/lib/libmcrypt.so.4.4.8
      0x7ffff7fab000     0x7ffff7fb2000     0x7000        0x0 
      0x7ffff7fcb000     0x7ffff7fce000     0x3000        0x0 [vvar]
      0x7ffff7fce000     0x7ffff7fcf000     0x1000        0x0 [vdso]
      0x7ffff7fcf000     0x7ffff7fd0000     0x1000        0x0 /usr/lib/x86_64-linux-gnu/ld-2.31.so
      0x7ffff7fd0000     0x7ffff7ff3000    0x23000     0x1000 /usr/lib/x86_64-linux-gnu/ld-2.31.so
      0x7ffff7ff3000     0x7ffff7ffb000     0x8000    0x24000 /usr/lib/x86_64-linux-gnu/ld-2.31.so
      0x7ffff7ffc000     0x7ffff7ffd000     0x1000    0x2c000 /usr/lib/x86_64-linux-gnu/ld-2.31.so
      0x7ffff7ffd000     0x7ffff7ffe000     0x1000    0x2d000 /usr/lib/x86_64-linux-gnu/ld-2.31.so
      0x7ffff7ffe000     0x7ffff7fff000     0x1000        0x0 
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]
  0xffffffffff600000 0xffffffffff601000     0x1000        0x0 [vsyscall]

```

In the output, it is evident that the heap memory is located immediately below the memory region allocated for the ‘dec’ ELF binary. 

Now we know where the ‘flag.enc’ file content will be allocated. We can analyze the core dump using pwn tools to find the heap in the core dump.

```bash
$ python3 -q

>>> from pwn import Corefile

>>> core = Corefile('core')
[x] Parsing corefile...
[*] '/home/remnux/HTB/RE/Sekure Decrypt/core'
    Arch:      amd64-64-little
    RIP:       0x7fca32b0f3eb
    RSP:       0x7fff92e111e0
    Exe:       '/home/user/Documents/RE/easy/Sekure Decrypt/release/debug/dec' (0x562e29888000)
    Fault:     0x1f204
[+] Parsing corefile...: Done

>>> print('\n'.join([str(mapping) for mapping in core.mappings]))
562e29888000-562e29889000 r--p 1000 /home/user/Documents/RE/easy/Sekure Decrypt/release/debug/dec
562e29889000-562e2988a000 r-xp 1000 /home/user/Documents/RE/easy/Sekure Decrypt/release/debug/dec
562e2988a000-562e2988b000 r--p 1000 /home/user/Documents/RE/easy/Sekure Decrypt/release/debug/dec
562e2988b000-562e2988c000 r--p 1000 /home/user/Documents/RE/easy/Sekure Decrypt/release/debug/dec
562e2988c000-562e2988d000 rw-p 1000 /home/user/Documents/RE/easy/Sekure Decrypt/release/debug/dec
562e2adce000-562e2adef000 rw-p 21000 
7fca32ac6000-7fca32ac9000 rw-p 3000 
7fca32ac9000-7fca32aee000 r--p 25000 /usr/lib/x86_64-linux-gnu/libc-2.30.so
7fca32aee000-7fca32c66000 r-xp 178000 /usr/lib/x86_64-linux-gnu/libc-2.30.so
7fca32c66000-7fca32cb0000 r--p 4a000 /usr/lib/x86_64-linux-gnu/libc-2.30.so
7fca32cb0000-7fca32cb3000 r--p 3000 /usr/lib/x86_64-linux-gnu/libc-2.30.so
7fca32cb3000-7fca32cb6000 rw-p 3000 /usr/lib/x86_64-linux-gnu/libc-2.30.so
7fca32cb6000-7fca32cba000 rw-p 4000 
7fca32cba000-7fca32cc0000 r--p 6000 /usr/lib/libmcrypt.so.4.4.8
7fca32cc0000-7fca32cd9000 r-xp 19000 /usr/lib/libmcrypt.so.4.4.8
7fca32cd9000-7fca32ce6000 r--p d000 /usr/lib/libmcrypt.so.4.4.8
7fca32ce6000-7fca32ce8000 r--p 2000 /usr/lib/libmcrypt.so.4.4.8
7fca32ce8000-7fca32cea000 rw-p 2000 /usr/lib/libmcrypt.so.4.4.8
7fca32cea000-7fca32cf1000 rw-p 7000 
7fca32d12000-7fca32d13000 r--p 1000 /usr/lib/x86_64-linux-gnu/ld-2.30.so
7fca32d13000-7fca32d35000 r-xp 22000 /usr/lib/x86_64-linux-gnu/ld-2.30.so
7fca32d35000-7fca32d3d000 r--p 8000 /usr/lib/x86_64-linux-gnu/ld-2.30.so
7fca32d3d000-7fca32d3e000 rw-p 1000 
7fca32d3e000-7fca32d3f000 r--p 1000 /usr/lib/x86_64-linux-gnu/ld-2.30.so
7fca32d3f000-7fca32d40000 rw-p 1000 /usr/lib/x86_64-linux-gnu/ld-2.30.so
7fca32d40000-7fca32d41000 rw-p 1000 
7fff92df3000-7fff92e14000 rw-p 21000 [stack]
7fff92f4d000-7fff92f50000 r--p 3000 
7fff92f50000-7fff92f51000 r-xp 1000 [vdso]
ffffffffff600000-ffffffffff601000 --xp 1000 [vsyscall]
```

Now we know from core dump that the heap is located at offset `0x562e2adce000` to offset `0x562e2adef000`. 

I had written a python script that will search the heap for each 16 byte value and AES decrypt to find potential flag. 

```bash
from pwn import Corefile
from Crypto.Cipher import AES

def extractPossibleFlag(corePath, startAddress, size, key, iv):
    core = Corefile(corePath)
    data = core.read(startAddress, size)

    for i in range(0, len(data), 16):
        chunk = data[i:i+16]

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(chunk)

        if decrypted.startswith(b'HTB'):
            return decrypted

def main():
    corePath = 'core'
    startAddress = 0x562e2adce000
    size = 2000    
    key = b'VXISlqY>Ve6D<{#F'
    iv = b'A' * 16

    flag = extractPossibleFlag(corePath, startAddress, size, key, iv)
    print(flag)

if __name__ == "__main__":
    main()
```

```bash
$ python3 ./decode.py 

[+] Parsing corefile...: Done
[*] '/home/remnux/HTB/RE/Sekure Decrypt/core'
    Arch:      amd64-64-little
    RIP:       0x7fca32b0f3eb
    RSP:       0x7fff92e111e0
    Exe:       '/home/user/Documents/RE/easy/Sekure Decrypt/release/debug/dec' (0x562e29888000)
    Fault:     0x1f204
    
b'HTB{t1m_l3arn_C}'
```
