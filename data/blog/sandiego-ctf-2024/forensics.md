---
title: San Diego CTF 2024 - Forensic Write Up
date: '2024-05-14'
draft: false
tags: ['Forensics', 'sandiego-ctf-2024']
summary: San Diego CTF 2024 - Forensic Write Up
---

# San Diego CTF 2024 - Forensic Write Up
+ k.eii
+ archive: https://github.com/jonscafe/ctfs-write-ups/tree/main/sandiegoctf-2024
---

## Watch the Waves 1
## ![image](https://hackmd.io/_uploads/HkXzsEem0.png)
from the given image, and the hint given by the chall. i think it has something to do with 'WAV'. So what first come to my mind is that the image is a wav file that is converted. So i write a simple script that turned the image into WAV by parsing its pixel value
![image](https://hackmd.io/_uploads/Sks6oElX0.png)

The result is a wav file with a voice recording of the flag in NATO Phonetic Code
![image](https://hackmd.io/_uploads/B1nSnEgX0.png)
```sdctf{l3tsg02th3b34ch}```

---

## Watch the Waves 2
## ![image](https://hackmd.io/_uploads/H135nNeQA.png)
still on the same topic, but the hint says to scan slowly.
i try to convert the png using the same script and got wav that sounds something i familiar with.

with the given hint from the chall description and sound that i familiar with, i notices that it was SSTV recording (Slow-scan television (SSTV), https://en.wikipedia.org/wiki/Slow-scan_television)

so i use SSTV decoder to decode it (i use this https://github.com/colaclanth/sstv)
![result](https://hackmd.io/_uploads/rkcraNgmC.png)
```sdctf{KK6UC_wuz-h3r3}```

