---
title: IrisCTF 2024 – Sharing is Caring
date: '2024-01-07'
draft: false
authors: ['legoclones']
tags: ['IrisCTF 2024', 'Misc', 'RF', 'Networks']
summary: 'Use DS-CDMA to isolate multiple signals being sent over the same communication channel'
canonical: 'https://justinapplegate.me/2024/irisctf-sharingiscaring'
---

## Sharing is Caring (Networks, 1 Solve)

> Sharing is caring, don’t ya know? Sharing a communications channel, that is!
>
> Eve is trying to read Alice’s messages, but she doesn’t know how to make sense of
> any of the data being received over the network. This isn’t your typical home network
> either, but something else within the network and communications space.
>
> Eve and Alice are the only people connected to the network in this area. They share
> the channel, and if anyone else joined the network, they would likewise have to share
> the channel. Alice has only 1 device and Eve controls the rest. Eve has the signal
> and of course her own keys, attached.
>
> Can you recover Alice’s messages?
>
> Hint - I wasn’t sure whether or not to put this in RF or networks, but decided on
> networks since the path to get to the solution is more on the theoretical side of
> the fence and applicable to more than just RF. Hopefully that should give you an idea
> of where to start!
>
> Author: skat

This problem was categorized as "Networks", although a note from the author said it could also fit in the RF (Radio Frequency) category. I went into this not really knowing much at all about the topic, but used ChatGPT, googlefu, and lots of analysis to figure out the solution!

Let’s first analyze the prompt because it gave important context that was needed to solve the challenge. There are two people sharing a single communication channel, Eve and Alice. Alice has a single device connected to the channel, presumably sending out the flag. Eve has multiple devices, which I’m assuming are also transmitting information on the channel. It also states that this "isn’t your typical home network", which means the communications/networking setup here is uncommon.

Here’s the important thing to note about channels: one of their biggest enemies is collisions. If two people transmit at the same time on the same channel, then their signals will mix (amplitudes will add up) and it can make the signals indistinguishable. So since both Alice and Eve are transmitting on the same channel, we need to figure out how to isolate Alice’s signal from Eve’s signals to retrieve the flag.

### Red Herring #1

My first thought went to something I learned about in my university’s Digital Communications class, CSMA. [CSMA stands for "carrier-sense multiple access"](https://en.wikipedia.org/wiki/Carrier-sense_multiple_access_with_collision_avoidance), and has two modes: collision avoidance and collision detection. CSMA is pretty much a way for multiple devices using the same communications channel to avoid and detect transmission collisions, which seems like our exact problem! I started doing research but everything I learned was pretty much just:

- Listen for data already being transmitted. If there’s data, then wait. If there’s not, then transmit.
- If a collision is detected, then both parties transmitting will stop, wait a random interval, then start again.

While important in modern-day networks, it didn’t seem super helpful in our case.

### Analyzing the Given Files

This is the perfect time to discuss and analyze the files we were presented with. Inside the compressed archive were 5 files: [`1.key`](https://justinapplegate.me/static/irisctf-sharingiscaring/1.key), [`2.key`](https://justinapplegate.me/static/irisctf-sharingiscaring/2.key), [`3.key`](https://justinapplegate.me/static/irisctf-sharingiscaring/3.key), [`4.key`](https://justinapplegate.me/static/irisctf-sharingiscaring/4.key), and [`signal.txt`](https://justinapplegate.me/static/irisctf-sharingiscaring/signal.txt). Each of the key files were filled with 200 random bytes, no strings or magic bytes or anything.

```bash
user@computer $ xxd 1.key
00000000: 8c8b 83b4 7c7f 3a38 022b 3380 e860 4abf  ....|.:8.+3..`J.
00000010: 6489 f9ad eb9b f503 517a cc0c dc2d 4470  d.......Qz...-Dp
00000020: b6b1 305b 4e62 8d18 75c2 3dcc 5226 10ed  ..0[Nb..u.=.R&..
00000030: dc7d a93c 3802 cd1b cf79 8c03 7ed2 27a4  .}.<8....y..~.'.
00000040: 9bbe 1290 e60b d4cb 18e6 63b1 3459 df4e  ..........c.4Y.N
00000050: 46fd 68d8 a061 f7bc cf80 337f 8f45 2e4a  F.h..a....3..E.J
00000060: 09d1 e66a 9ee4 2e3f d078 ad44 9c4f 4ef9  ...j...?.x.D.ON.
...
```

My guess was each key corresponded to a device on the channel, so there were 5 devices total (1 for Alice, 4 for Eve). Also, since they’re called "keys", I figured they were decryption keys or something, but couldn’t figure out what for. Decryption keys aren’t typically this long, plus 200 bytes is an odd keysize. My research yielded nothing, so I set those aside and tried to understand the last file, `signal.txt`.

`signal.txt` contained a single array with 1,280,000 integers, ranging from -5 to +5. I did some analysis and found out that the only values were `[-5, -3, -1, 1, 3, 5]`, so odd numbers. I figured the order was significant, and perhaps even a crude way of shipping data points meant to be charted. Each element in the list was a value meant to be plotted on a y-axis, and each point was simply equidistant apart on the x-axis (probably some measure of time). I had ChatGPT generate [a Python script](https://justinapplegate.me/static/irisctf-sharingiscaring/plot.py) that would chart the first 50 values for me:

![Time-Amplitude signal plot](/static/images/irisctf-2024/chart.png)

At this point I had several questions pop up:

1. Why is the range `-5` to `5`?
2. Why are there only odd numbers? More specifically, why is there never a `0` value?
3. Why are there a million values?
4. What do keys have to do with this?
5. Why doesn’t the graph show nice, even sine waves?

### Rules of Engagement

I started to hypothesize what the answers for these questions might be until I found an answer that satisfied them all, giving me the rules of transmission in this situation. First let’s review collisions; let’s say there are 2 devices on the same channel, both sending waves with an amplitude of `+1`. These will collide and a receiver will only see a wave with an amplitude of `+2` (assuming the waves are synchronized). However, if one device is transmitting with an amplitude of `+1` and the other with an amplitude of `-1`, then they will cancel out and the receiver won’t see any signal.

Now imagine a situation with 5 devices! When you see a signal with an amplitude of `+1`, what does that mean? It could be that only one device is transmitting with an amplitude of `+1`, 3 devices are transmitting with amplitudes `+1`, `+1`, and `-1`, you can’t be sure!

I had assumed that the 5 devices could transmit or not transmit whenever they wanted. If this was the case, there’s approximately a 0% chance that amplitudes would only be odd with 1.2 million data points. HoWeVeRrR, if we assume that all 5 devices are **always** transmitting, and either with an amplitude of `-1` or `+1`, then that issue is resolved. The sum of those 5 amplitudes will **always have to be odd**, and the max/min fit `+5`/`-5`.

This resolves questions 1, 2, and 5, but introduces a sixth one: How can I isolate Alice’s signal if 5 devices are always transmitting and colliding at the same time?

### More Patterns... They’re Everywhere!

I thought to myself, "Well, what do I know about the data Eve is transmitting? Nothing..... or at least that I know of. All I have are the keys, maybe for some reason they’re transmitting the keys?" I went with that thought and tried some things out.

Eventually, I found that if you turn the 200-byte keys into 1600-bit binary strings, then treat a `1` as a signal of `-1`, and a `0` as a signal of `1`, adding the amplitude for the first 1600 bits ALWAYS gave a sum that was +/- 1 of the signal. Here’s an example:

- First 4 bytes of `1.key` -> `8c8b83b4` = `10001100 10001011 10000011 10110100`
- Translate all `1` into `-1`, and `0` into `1` = `[-1, 1, 1, 1, -1, -1, 1, 1, -1, 1, 1, 1, -1, 1, -1, -1, -1, 1, 1, 1, 1, 1, -1, -1, -1, 1, -1, -1, 1, -1, 1, 1]`

I did this for all 200 bytes of all 4 keys and ended up with 4 big arrays:

```
1.key - [-1, 1, 1, 1, -1, -1, 1, 1, ...]
2.key - [1, 1, -1, 1, -1, -1, 1, 1, ...]
3.key - [-1, -1, 1, -1, -1, 1, 1, 1, ...]
4.key - [1, 1, -1, -1, -1, 1, 1, -1, ...]
```

Now since all these signals are being transmitted at the same time, I should add them up to see what the total signal looks like for 4 of the 5 devices on the channel - `[0, 2, 0, 0, -4, 0, 4, 2, ...]`. How does the signal amplitude compare? `[-1, 3, 1, -1, -3, -1, 5, 3, ...]`. If you look carefully, you’ll notice that each of signal amplitude values are within `+/-1` of the numbers I calculated. This held true for the first 1600 bits, which was too many to be a coincidence.

This meant I could find the difference and use that to calculate what the amplitude of the first 1600 bits of the last device on the channel, which is likely Alice’s key! (note I still didn’t know what to do with it, but at least I had it!)

I wrote a quick python script and [got Alice’s key](https://justinapplegate.me/static/irisctf-sharingiscaring/alice.key):

```bash
user@computer $ xxd alice.key
00000000: 94e7 b524 b466 10b1 2604 a6d3 29a5 6911  ...$.f..&...).i.
00000010: bf95 b7b3 5ae5 96a4 2a40 b939 4755 ba35  ....Z...*@.9GU.5
00000020: f17b d723 d7a2 1808 f26c 7dc4 d29f 1cb8  .{.#.....l}.....
...
```

That was the last pattern that I needed to find before I put all the puzzle pieces together.

### CDMA

I was still struggling to figure out how it was possible to isolate a single signal from a collision mess of 5 signals when I asked ChatGPT.

![GPT Response](/static/images/irisctf-2024/gpt1.png)

![GPT Response](/static/images/irisctf-2024/gpt2.png)

I knew it wasn’t TDMA or FDMA because these devices were transmitting with the same frequencies at the same time, but CDMA?? I had never heard of that! Apparently it uses "unique codes" (just like keys??) to differentiate their signals in some way. I went ahead and did more investigation into CDMA. I stumbled upon [this website](http://www.wirelesscommunication.nl/reference/chaptr05/cdma/dscdma.htm) that described CDMA pretty well.

![CDMA](/static/images/irisctf-2024/chip.gif)

A long, unique "code" (also known as a PN code, PRN code, or "key" in our situation) is used to send a message by multiplying it with a single bit from the message and sending that signal out. Remember how `1.key` was encoded as the signal `[-1, 1, 1, 1, -1, -1, 1, 1, ...]`? Well, if the first bit from the message is a `1`, then that signal is sent out. However, if the first bit is `0`, then the opposite of that signal is sent out (`[1, -1, -1, -1, 1, 1, -1, -1, ...]`). The entire code/key is sent for a single bit of the message, which meant 1600 signal bits gave us 1 message bit. That’s a HUGELY inefficient ratio, but makes sense why 1.2 million signal bits were sent!

That answers all the questions I posed _except_ how to isolate the signals from one another, even if encoded in DS-CDMA. But some reasoning and Python helped me there! We have all 5 keys (or perhaps the opposite of Alice’s key, but that can easily be resolved with testing), and know only those 5 devices are transmitting. Each device will either transmit their key or the opposite of their key, so 2 possibilities. With 5 devices, `2**5` is 32, meaning there are only 32 possible combinations of signals sent out. If I mapped each of those 32 possibilities out and split my signal into 1600-bit chunks, I could figure out which bits were being sent for each device at the same time!

I decided to use MD5 hashes of these 1600-bit variations to match to our 32 possibilities and wrote [this cool, little, script](https://justinapplegate.me/static/irisctf-sharingiscaring/solve.py) using perfect programming technique:

```py
import math
from hashlib import md5


### SIGNAL DATA ###
signal_data = eval(open('signal.txt','r').read())

# split signal_data into lists of 1600
data_segments = [signal_data[i:i+1600] for i in range(0, len(signal_data), 1600)]
#print(data_segments)


### KEYS ###
# keys in binary format (ie b'\x99\x34\x12')
keys_b = [0, 0, 0, 0, 0]
keys_b[0] = open('1.key','rb').read()
keys_b[1] = open('2.key','rb').read()
keys_b[2] = open('3.key','rb').read()
keys_b[3] = open('4.key','rb').read()
keys_b[4] = open('alice.key','rb').read()

# keys in string format (ie ['1','0','1','0','1','0','1','0'])
keys_s = []
for k in keys_b:
    keys_s.append([x for x in''.join([bin(x)[2:].zfill(8) for x in k])])

# keys in decoded format where 1 is -1 and 0 is 1
keys_d = []

for k in keys_s:
    tmp0 = []
    tmp1 = []
    for i in range(len(k)):
        if k[i] == '1':
            tmp0.append(-1)
            tmp1.append(1)
        else:
            tmp0.append(1)
            tmp1.append(-1)

    keys_d.append({'0':tmp0,'1':tmp1})



### MESSAGE VARIATIONS ###
def get_seq(key1, key2, key3, key4, key5):
    retval = []
    for i in range(len(key1)):
        retval.append(key1[i] + key2[i] + key3[i] + key4[i] + key5[i])

    hash = md5(''.join([str(x) for x in retval]).encode()).hexdigest()
    return hash
variations = []

# i know this isn't good programming but idc
variations.append(("00000",get_seq(keys_d[0]['0'],keys_d[1]['0'],keys_d[2]['0'],keys_d[3]['0'],keys_d[4]['0'])))
variations.append(("00001",get_seq(keys_d[0]['0'],keys_d[1]['0'],keys_d[2]['0'],keys_d[3]['0'],keys_d[4]['1'])))
variations.append(("00010",get_seq(keys_d[0]['0'],keys_d[1]['0'],keys_d[2]['0'],keys_d[3]['1'],keys_d[4]['0'])))
variations.append(("00011",get_seq(keys_d[0]['0'],keys_d[1]['0'],keys_d[2]['0'],keys_d[3]['1'],keys_d[4]['1'])))
variations.append(("00100",get_seq(keys_d[0]['0'],keys_d[1]['0'],keys_d[2]['1'],keys_d[3]['0'],keys_d[4]['0'])))
# ...
print(variations)


### LOOP THROUGH SEGMENTS ###
for segment in data_segments:
    hash = md5(''.join([str(x) for x in segment]).encode()).hexdigest()

    for variation in variations:
        if hash == variation[1]:
            print(variation[0][-1],end='')
            break
    else:
        print("ERROR: hash not found")
```

Running the script:

```bash
user@computer $ python3 solve.py
[('00000', '0d117435c56281b054522b58cdcb64fe'), ('00001', '2a1c1afc86d487558c615435f288bb7e'), ('00010', '17e8ae0b4c6135839883edb6474556ba'), ('00011', '13fb6b827c11f4e37a35a69f256a4b1d'), ('00100', '5b880d5f9efdb8110b06927b1970b8b2'), ('00101', '69556b97fb9ac2a162f4d5a633566bce'), ('00110', 'c831e945c9b78871d08af0639b606fc1'), ('00111', '7d8ffc868b8b2896f9a90f83a9f5cf93'), ('01000', '28a6e21c237ca53f13bba8e5829d7783'), ('01001', '24d84770cb6bb7d2359fc0b15e0f63f8'), ('01010', '989aaab62cac2639b1914ee5b7bff47e'), ('01011', '42246aaecd145b87855ac6d7f3e145ba'), ('01100', '128ab2324bacb26de1f55cec5f3a83f0'), ('01101', '2d629a5610238046d868fd5283d86db5'), ('01110', '9534dd64a74bfe14b88d70cb37d70824'), ('01111', 'ff353f0ef94c906d138174c382497354'), ('10000', '3ff55e64c1dd2f2f3f5d93d3595780a2'), ('10001', '5654bfafc4a3631e53454d38b96c7cc8'), ('10010', '636e5c3c098dd7391f6f18011ba2fd05'), ('10011', '0de67b7b65a73a7e54abc3c0c24f96a3'), ('10100', 'ae61d3ceb508ba6ead8a3f9489aba9e4'), ('10101', 'a608fdc445bed490ed983db2ffbe1db5'), ('10110', 'df11e52e16429ee547a0cca1b14b5f09'), ('10111', 'ec4a69e1554b9eef0a9e2b238bb2a588'), ('11000', 'e211579051e5df5a8c69d5631bb9982d'), ('11001', '57a1784ca874a96712d6c48633cc214d'), ('11010', '3eb893ec606ae2cd53e93565d1847708'), ('11011', '66701f5634aa2863343afdc0b2fa1ad2'), ('11100', '619dca459b3e9cf8e88392cfd393cc4c'), ('11101', 'e2e86a83556b27b8bdb1a0bc48260684'), ('11110', '5fda6619728927d9011400f7caf4e1f9'), ('11111', '969dbb210db5f3dfb2083788534c976d')]
01001000011001010111100100100000010000010110110001101001011000110110010100101100001000000110100001100101011100100110010100100111011100110010000001110100011010000110010100100000011001100110110001100001011001110011101000100000011010010111001001101001011100110110001101110100011001100111101100110000011010000101111101101110001100000101111101111001011011110111010101110110001100110101111101100100001100110110011001100101011000010111010000110011011001000101111101110011011100000111001000110011011000010110010001011111011100110011000101100111011011100110000101101100011100110101111101100001011011100110010001011111001100010110111001110100001100110111001001100011011001010111000001110100001100110110010001011111011011010111100101011111011000110011000001101101011011010111001101111101000000000000000000000000
```

![Flag](/static/images/irisctf-2024/flag.png)

**Flag:** `irisctf{0h_n0_youv3_d3feat3d_spr3ad_s1gnals_and_1nt3rcept3d_my_c0mms}`
