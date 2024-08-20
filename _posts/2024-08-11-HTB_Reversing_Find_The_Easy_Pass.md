---
layout:	post
title:  "Find The Easy Pass"
date:   2024-08-11 04:11:11 +0200
categories: [HTB Track - Reversing]
tags: [HTB]
---


The challenge file was an executable which when executed prompt to enter a password.

![GUI1](/images/2024-08-11-HTB_Reversing_Find_The_Easy_Pass/1.png)

To check, ‘ape’ was entered as password which failed obviously.

![GUI2](/images/2024-08-11-HTB_Reversing_Find_The_Easy_Pass/2.png)

The challenge binary was loaded in IDA and cross-reference to “Wrong Password!” string was searched which lead to main logic of the check. 

![IDA](/images/2024-08-11-HTB_Reversing_Find_The_Easy_Pass/3.png)

Then challenge binary was loaded in x32dbg to check the flag.

![x32dbg](/images/2024-08-11-HTB_Reversing_Find_The_Easy_Pass/4.png)

```bash
HTB{fortran!}
```