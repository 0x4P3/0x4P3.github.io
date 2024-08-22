---
layout:	post
title:  "IRCWare"
date:   2024-08-11 06:11:11 +0200
categories: [HTB Track, Intro to Reversing]
tags: [HTB]
---

The challenge binary is a 64-bit ELF file format as can be seen below. Also this file is stripped so the debugging symbols will not be present in this file. This will make the analysis a bit harder.

```bash
file ircware 
ircware: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

On executing the challenge binary, it prints ‘EXCEPTION! ABORT’ and exits. 

```bash
$ ./ircware 
EXCEPTION! ABORT
```

First thing I usually like to do is load the binary in Ghidra. Since this binary is stripped, it might be harder to locate main. Lets analyze from entry().

![Ghidra](/images/2024-08-11-HTB_Reversing_IRCWare/1.png)

First there is syscall to getrandom which will generate some random bytes.

After that there is call to initiateConnection().

![Ghidra](/images/2024-08-11-HTB_Reversing_IRCWare/2.png)

- Inside the initiateConnection() function, it creates socket and initiate connection. It initializes connection at IP 0x400007f and port 0x401f.
- Using the Cyberchef, the IP and port were found to be 127.0.0.1 and 8000 respectively.
    
    ![CyberChef IP](/images/2024-08-11-HTB_Reversing_IRCWare/3.png)

    ![CyberChef Port](/images/2024-08-11-HTB_Reversing_IRCWare/4.png)

After that, it checks if the connection is successful as can be seen below.

![Ghidra](/images/2024-08-11-HTB_Reversing_IRCWare/5.png)

If connection failed, it will syscall write to output “EXCEPTION! ABORT” and then exits. This was the case when executed before since we were not listening on 127.0.0.1:8000.

![Ghidra](/images/2024-08-11-HTB_Reversing_IRCWare/6.png)

If the connection succeed,  it will first call sysWriteWrapper() function that contain syscall write to output 3 message to remote connected terminal.

![Ghidra](/images/2024-08-11-HTB_Reversing_IRCWare/7.png)

After that it enters a loop, where it calls sysReadWrapper() function that contain syscall read to listen for any IRC command. Then there is call to mainFunctionality() function that handles the commands. And the commands that it handles is shown below.

![Ghidra](/images/2024-08-11-HTB_Reversing_IRCWare/8.png)

To retrieve the flag, we need a password. The entered password is validated at this step as shown in image below. The password is processed through some algorithm using a key ‘RJJ3DSCP’.

![Ghidra](/images/2024-08-11-HTB_Reversing_IRCWare/9.png)

Lets understand the algorithm:

- The pass has to be greater than 64, i.e. pass > A.
- The pass has to be smaller than 91, i.e. pass < Z.
- The pass + 17 is equal to the key.

So based on this, we can decrypt it. We can use a dictionary of A-Z. Then we can subtract 17 to the key ‘RJJ3DSCP’ and retrieve the pass.

I wrote a simple python script to achieve this.

```python
def shift_letter(letter, shift):
    if 'A' <= letter <= 'Z':
        return chr((ord(letter) - ord('A') - shift) % 26 + ord('A'))
    return letter

def shift_string(key, shift):
    return ''.join(shift_letter(char, shift) for char in key)

key = 'RJJ3DSCP'
shift = 17
key = shift_string(key, shift)
print(key)
```

The password that we get is ASS3MBLY.

![Ghidra](/images/2024-08-11-HTB_Reversing_IRCWare/10.png)
Lets now use this password to retrieve the key. But first lets listen on 127.0.0.1:8000 using Netcat.

```bash
nc -lv 127.0.0.1 8000
Listening on localhost 8000
```

After executing the challenge binary, following was prompt on Netcat terminal. The password was passed and flag was retrieved.

```bash
nc -lv 127.0.0.1 8000

Listening on localhost 8000
Connection received on localhost 59290

NICK ircware_2265
USER ircware 0 * :ircware
JOIN #secret

PRIVMSG #secret :@pass ASS3MBLY
PRIVMSG #secret :Accepted

PRIVMSG #secret :@flag
PRIVMSG #secret :HTB{m1N1m411st1C_fL4g_pR0v1d3r_b0T}
```
