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
``
Found signature in [Malware Bazaar]() via Google dorking the IoC: `"`
<details>
  <summary>Show Answer</summary>
  <code>dridex</code>
  <br>
  Found signature in <a href="https://bazaar.abuse.ch/sample/7103c9d1c2a64b80a4b69e3d91487b602fd4ede836722fa9c0daf4fe09a2b7cd/">Malware Bazaar</a> via Google dorking the IoC: <code>intext:"rilaer.com/IfAmGZIJjbwzvKNTxSPM/ixcxmzcvqi</code>
</details>

<br>

---