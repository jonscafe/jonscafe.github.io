---
title: Mirea CTF 2024 Forensic Writeup
date: '2024-05-02'
draft: false
tags: ['Forensics', 'mirea-ctf-2024']
summary: Mirea CTF 2024 Forensic Writeup
---

# MireaCTF 2024 - Quals
### SNI CTF Team - Forensic 2/2 solves writeup
#### solved by: k.eii & TunangannyaChizuru
---
#### 1. Optography
Given chall.vmem (VMWare Memory Dump). From the challname we knew that we must find out what is the last screen of the image memory dump
*Optography definition: (sometimes its very good to find out the hint given my the chall description)*
![image](https://hackmd.io/_uploads/SJsFDFgf0.png)

So we analyze the memory dump using volatility3. First of all try to scan the pslist/pstree to see what proccess has been runned by the computer. Found out there are mspaint.exe so i dump it using memdump plugins of volatility3. using [w00tsec's](https://w00tsec.blogspot.com/2015/02/extracting-raw-pictures-from-memory.html) method, we can view the screen by opening the dumped memory as raw image (rename from .dmp into .data and open it in GIMP)
![image](https://hackmd.io/_uploads/rkfAuKxG0.png)
*flag: mireactf{dump_scr33n_fr0m_m3m0ry_1s_based}*

#### 2. SOC Analyst
given .pcapng file, we need to analyze it to find the flag.
while analyzing, we found out there are a packet that transmit some "sus" strings. 
![image](https://hackmd.io/_uploads/BJzttKgfR.png)

following  the packet we got this base64 lookalike string
![image](https://hackmd.io/_uploads/H1GiYKeGC.png)

using dcode.fr we found out that the string is base58 encoded so we try to decode it and got a binary from that.
![image](https://hackmd.io/_uploads/B1t0FYlMR.png)
![image](https://hackmd.io/_uploads/Bk3M9Yxf0.png)

download the elf and try to run it (im too lazy to do reverse lol)
we got this string: `bf}jnl{it8g<}<P>:P:?b<8g>a9P:8}a9<P;m?z8P8g>:P8}ii>lr`

turns out it was xored and i found it by using dcode.fr again lol
![image](https://hackmd.io/_uploads/HJ4d9YgfA.png)
