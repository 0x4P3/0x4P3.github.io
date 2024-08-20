---
layout:	post
title:  "Bypass"
date:   2024-08-11 10:11:11 +0200
categories: [HTB Track - Reversing]
tags: [HTB]
---


The challenge file was an executable that prompted for a username and password when executed. The ‘ape’ was entered as both username and password that failed obviously.

```
Enter a username: ape
Enter a password: ape
Wrong username and/or password
```

Upon inspecting the executable with CFF Explorer, it was identified as a .NET application.

![CFF Explorer](/images/2024-08-11-HTB_Reversing_Bypass/1.png)

Since it's a .NET application, we can analyze it in Intermediate Language instead of assembly code. For this purpose, we can use dnSpy tool. The binary was loaded in dnSpy and the entry point can be seen as method 0 of class 0.

![dnSpy](/images/2024-08-11-HTB_Reversing_Bypass/2.png)

The method 0 of class 0 can be seen below.

![dnSpy](/images/2024-08-11-HTB_Reversing_Bypass/3.png)

First there is call to method 1 of class 0 which return value is saved to flag. 

The method 1 is the part that ask for username and password and save it in text and text2 respectively. But the method 1 returns false without any validation regardless what the input is.

![dnSpy](/images/2024-08-11-HTB_Reversing_Bypass/4.png)

The returned value of method1 is then passed to flag, which is then saved to flag2 which is validated. Since this is always false no matter what the input is. We can add breakpoint on validation and set the flag2 to true.

![dnSpy](/images/2024-08-11-HTB_Reversing_Bypass/5.png)

After successfully validating, it will call method 2 of class 0. And there is some kind of validation of flag.

![dnSpy](/images/2024-08-11-HTB_Reversing_Bypass/6.png)

When debugging, it was found that it ask for secret key as can be seen below.

![dnSpy](/images/2024-08-11-HTB_Reversing_Bypass/7.png)

The secret key it validated with is `ThisIsAReallyReallySecureKeyButYouCanReadItFromSourceSoItSucks`. So the validation is incorrect hence flag is false. 

Instead of re-executing the program and entering the correct secret key, lets set the flag to true to get the flag.

![dnSpy](/images/2024-08-11-HTB_Reversing_Bypass/8.png)

The flag is then printed in the terminal.

![Flag](/images/2024-08-11-HTB_Reversing_Bypass/9.png)

```bash
HTB{SuP3rC00lFL4g}
```