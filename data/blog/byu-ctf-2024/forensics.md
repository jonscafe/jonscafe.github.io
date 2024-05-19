---
title: BYUCTF 2024 Forensic Write-Up
date: '2024-05-19'
draft: false
tags: ['Forensics', 'byu-ctf-2024']
summary: BYU CTF 2024 Forensic Writeup
---

# BYUCTF 2024 - Forensics Write-Up
- k.eii
- Archive: [GitHub Repository](https://github.com/BYU-CSA/BYUCTF-2024-Public/tree/main/forensics)
- 6/7 solved

---

## Who am I
<img src="https://hackmd.io/_uploads/S1XSX0LmC.png" width="300px" alt="Who am I"></img>

Right-click -> properties

## Steak (The description is too long)
first of all i was tryin to do it by finding way to read the corrupted image. but i got an idea why didnt i try to search on the image's hex. so the logic will be:
find the header and eof chunk of the example, and find it on the corrupted image to extract it.
header:
![image](https://hackmd.io/_uploads/BJOBVRU70.png)
EOF:
![image](https://hackmd.io/_uploads/rJPINAIQC.png)

<img src="https://hackmd.io/_uploads/SyjH70ImA.png" width="700px" alt="Steak"></img>

Header is: 13 37 BE EF F2 : 00E00000  
EOF is: 4D 6F 6F 6F : 00E8F8A0  
Search it on MadCow.001 and extract it.

Decrypt using the given script. Got the flag as png.

## Did Nobody See?
<img src="https://hackmd.io/_uploads/rJ5bXRU70.png" width="300px" alt="Did Nobody See?"></img>

the chall asked us to find IP of the DNS registered on the Registry keys
[[check at the screenshot]](https://commons.erau.edu/cgi/viewcontent.cgi?article=1117&context=jdfsl)
<img src="https://hackmd.io/_uploads/SkGfQCUm0.png" width="600px" alt="Did Nobody See?"></img>
<img src="https://hackmd.io/_uploads/H1FMm0IQA.png" width="600px" alt="Did Nobody See?"></img>

## Not Again! I've been BitLockered out of my own computer!
<img src="https://hackmd.io/_uploads/Bk3LmCIQ0.png" width="300px" alt="BitLocker"></img>

Given memory dump, I tried using Volatility3 and found nothing. The challenge mentioned FVEK, and I found a plugin for Volatility (old) to dump the FVEK ([Source](https://security.stackexchange.com/questions/214671/what-is-the-purpose-of-the-volume-master-key-in-bitlocker)). However, I couldn't do it because the image profile was unknown ([GitHub](https://github.com/breppo/Volatility-BitLocker)). 
<img src="https://hackmd.io/_uploads/HJX_XCIX0.png" width="600px" alt="BitLocker Plugin"></img>

Used Memprocfs to parse the memory dump as files:
<img src="https://hackmd.io/_uploads/HJ9_XA8X0.png" width="600px" alt="Memprocfs"></img>
<img src="https://hackmd.io/_uploads/S1Cum0IQA.png" width="600px" alt="Memprocfs"></img>

Found the image profile, tried again but got nothing. Copied memory.dmp and used Volatility (old) on it and got the FVEKs:
<img src="https://hackmd.io/_uploads/BJBtQRI7A.png" width="600px" alt="FVEKs"></img>

## Not Sure I'll Recover From This
<img src="https://hackmd.io/_uploads/S1dYmA87C.png" width="300px" alt="Recovery"></img>

Because the challenge asked for the user’s credential, we’ll check the SAM registry that contains user account data:
[documentation, check here](https://www.forensicfocus.com/forums/general/user-passwords-in-the-registry/)
<img src="https://hackmd.io/_uploads/B16YXR8XR.png" width="600px" alt="SAM Registry"></img>

## The Worst Challenge
<img src="https://hackmd.io/_uploads/HJLcQ08m0.png" width="600px" alt="Worst Challenge"></img>

Given file .txt that seems to have null bytes. But it wasn't; there are 01’s, maybe it was the flag written in bytes.
<img src="https://hackmd.io/_uploads/H1gocX08XA.png" width="600px" alt="Null Bytes"></img>

### solv.py
<img src="https://hackmd.io/_uploads/SJ7omRI70.png" width="600px" alt="solv.py"></img>
