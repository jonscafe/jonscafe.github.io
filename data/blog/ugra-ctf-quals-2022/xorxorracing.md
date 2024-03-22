---
title: Ugra CTF Quals 2022 – Хохорейсинг
date: '2022-03-04'
draft: false
authors: ['thebish0p']
tags: ['Ugra CTF Quals 2022', 'Crypto', 'XOR', 'Automation', 'Web Socket']
summary: 'Sometimes you have to google the outputs xD'
---

## Хохорейсинг (`xorxoracing`, 100)

> by Kalan
>
> If you've already played enough Picky Snake, it's time to switch to another game, simpler.
>
> https://xoxoracing.q.2022.ugractf.ru/cf04601aff9c10bd/

We start by checking the web page and we can see that we can input an Encryption Key. We input `test` as key and we get an encrypted text:

![Testing key](/static/images/ugra-ctf-quals-2022/xorxoracing/test.png)

We have a new input field available `Original Text` so the whole point is guessing the original text.
After analysing the HTML source code we can see a js file that explain how the whole game works. Basically we input a key and get the ciphertext, however that ciphertext is damaged because we will have many characters hidden (replaced).

```JavaScript
const socket = new WebSocket(`${window.location.href.replace('http', 'ws')}ws`);

const onClose = e => {
};

const onError = e => {
};

const onMessage = e => {
    try {
        data = JSON.parse(e.data);
    } catch (_) {
        // invalid data from server
        return;
    }

    if (data.flag !== undefined) {
        document.getElementById("flag").innerText = data.flag;
        if (data.flag.length >= 70) {
            document.getElementById("progress").className = "progress done";
        }
    }

    if (data.countdown !== undefined) {
        document.getElementById("timer").innerText = Math.floor(data.countdown / 10) + "" + (data.countdown % 10);
    }

    if (data.ciphertext !== undefined) {
        document.getElementById("ciphertext").innerText = data.ciphertext;
        document.getElementById("ciphertext").innerHTML = document.getElementById("ciphertext").innerHTML.replace(/Р–/g,
                                                          "<img class=eeee src=/static/err.svg style=width:1ch alt=err>");
        document.getElementById("seg-1").className = "segment active";
        document.getElementById("seg-2").className = "segment";
        document.getElementById("text").disabled = false;
        document.getElementById("submit-text").disabled = false;
        document.getElementById("key").disabled = true;
        document.getElementById("submit-key").disabled = true;
        document.getElementById("text").focus();
    }

    if (data.text !== undefined) {
        document.getElementById("text").value = data.text;
    }

    if (data.status !== undefined) {
        document.getElementById("text").parentNode.className = "field " + data.status;
        if (data.status) {
            document.getElementById("seg-1").className = "segment";
            document.getElementById("seg-2").className = "segment";
            document.getElementById("text").disabled = true;
            document.getElementById("submit-text").disabled = true;
            document.getElementById("key").disabled = true;
            document.getElementById("submit-key").disabled = true;
        } else {
            document.getElementById("seg-1").className = "segment";
            document.getElementById("seg-2").className = "segment active";
            document.getElementById("text").disabled = true;
            document.getElementById("submit-text").disabled = true;
            document.getElementById("key").disabled = false;
            document.getElementById("submit-key").disabled = false;
            document.getElementById("key").focus();
            document.getElementById("ciphertext").innerHTML = "&nbsp;";
            document.getElementById("text").value = "";
            document.getElementById("key").value = "";
        }
    }
};

socket.onclose = onClose;
socket.onerror = onError;
socket.onmessage = onMessage;

document.getElementById("key").focus();

document.getElementById("submit-text").onclick = e => {
    socket.send(JSON.stringify({"text": document.getElementById("text").value}));
};
document.getElementById("submit-key").onclick = e => {
    socket.send(JSON.stringify({"key": document.getElementById("key").value}));
};
document.getElementById("text").onkeypress = e => {
    if (e.keyCode == 13) {
        document.getElementById("submit-text").onclick(e);
    }
};
document.getElementById("key").onkeypress = e => {
    if (e.keyCode == 13) {
        document.getElementById("submit-key").onclick(e);
    }
};

window.setInterval(() => {
    let t = Math.max(0, parseInt(document.getElementById("timer").innerHTML) - 1);
    document.getElementById("timer").innerHTML = Math.floor(t / 10) + "" + (t % 10);
}, 1000);

```

The whole communication is happening through websockets. We send a key → Receive a ciphertext → Send plaintext → Receive original plaintext to compare:

![WS Communication](/static/images/ugra-ctf-quals-2022/xorxoracing/communication.png)

I wrote a small script at first to just print out plaintexts and I noticed that the length of each plaintext is 40 chars. And I notice something really interesting and that each sentence comes from the US constitution.

```python
import json
from websocket import create_connection

ans = 'a'
key = 'test'
ws = create_connection("wss://xoxoracing.q.2022.ugractf.ru/cf04601aff9c10bd/ws")

for _ in range(10):
    ws.recv()
    ws.send(json.dumps({"key": key}))
    ciphertext_data =  ws.recv()
    ct = json.loads(ciphertext_data)['ciphertext']
    ws.send(json.dumps({"text":ans}))
    plaintext_data =  ws.recv()
    pt = json.loads(plaintext_data)['text']
    print(pt)
    print('============================================')

ws.close()
```

Output:

```
s pass any Bill of Attainder ex post fac
============================================
ations made by Law and a regular Stateme
============================================
subject to the jurisdiction thereof for
============================================
y subsequent Term of ten Years in such M
============================================
rect Taxes shall be apportioned among th
============================================
e the Adoption of this Constitution shal
============================================
cipation of any slave but all such debts
============================================
or proposing Amendments which in either
============================================
o construed as to affect the election or
============================================
```

Okay so the plaintexts are from the US consitution and don’t have any punctuation or new lines. Now let’s try to input 40 chars key → Xor it with ciphertext and see how it looks.

```python
import json
from websocket import create_connection

ans = 'a'
key = 'a'*40
ws = create_connection("wss://xoxoracing.q.2022.ugractf.ru/cf04601aff9c10bd/ws")

for _ in range(10):
    ws.recv()
    ws.send(json.dumps({"key": key}))
    ciphertext_data =  ws.recv()
    ct = json.loads(ciphertext_data)['ciphertext']
    xor_list = [chr(ord(a) ^ ord(b)) for a,b in zip(ct, key)]
    expected_pt = ''.join(xor_list).replace('ѷ', 'X')
    ws.send(json.dumps({"text":ans}))
    plaintext_data =  ws.recv()
    pt = json.loads(plaintext_data)['text']
    print(expected_pt)
    print(pt)
    print('='*40)

ws.close()
```

Output:

```
X NX XXX XXXXXXX XXX XXXXXXXXXXXX XXX XX
n No law varying the compensation for th
========================================
 XX X RXXXXXXXXXXXXX XXX XXXXX XXX XXXX
 be a Representative who shall not have
========================================
XXXX XX XXXXXX X LXX XX XXXXXXXXX XX XXX
fore it become a Law be presented to the
========================================
XXX XXXXXXXXXXX XXX XXXXXX TXXX XXXXXXXX
the legislature may direct This amendmen
========================================
X XXXXXX RXXXXXXXXXXXXXX XXX XXXXXX TXXX
e chosen Representatives and direct Taxe
========================================
XXX XX XXXXX XX VXXXPXXXXXXXX XXXXX XX X
ber of votes as VicePresident shall be t
========================================
XXX XX XXXX XXXXXXXXX XXXXXXXXXXXX XXXXX
eof to make temporary appointments until
========================================
XXXX XXXXXX XXXX XX CXXXX XX RXXXXXXXX X
nded unless when in Cases of Rebellion o
========================================
X XXXXXX MXXXXXXXX XXX CXXXXXX JXXXXX XX
r public Ministers and Consuls Judges of
========================================
XXXXXXX XXXXXXX XX XXXXXXXXX XX XXX CXXX
hteenth article of amendment to the Cons
========================================
```

At this point I came up with the solution. Just convert the US constitution to a txt file, remove all new lines, remove new lines and just replace `X` with a `.` which would create a valid regex pattern then use that to get the plaintext and send it to the server. I wrote the following script and the output reveal the flag:

```python
import json
import re
from websocket import create_connection
g = {}
ans = 'a'

ws = create_connection("wss://xoxoracing.q.2022.ugractf.ru/cf04601aff9c10bd/ws")

with open('final.txt', 'r') as f:
    final = f.read()

while 1:
    ws.recv()
    key = "a"*40
    ws.send(json.dumps({"key": key}))
    ciphertext_data =  ws.recv()
    ct = json.loads(ciphertext_data)['ciphertext']
    xor_list = [chr(ord(a) ^ ord(b)) for a,b in zip(ct, key)]
    pattern = ''.join(xor_list).replace('ѷ', '.')

    try:
        ans = re.findall(pattern, final)[0]
    except:
        ans = 'miaw'


    ws.send(json.dumps({"text":ans}))
    plaintext_data =  ws.recv()
    pt = json.loads(plaintext_data)['text']
    flag = json.loads(plaintext_data)['flag']

    if flag != '':
        print(flag)
```

Output revealing the flag:

```
ug
ugra_go_
ugra_go_go
ugra_go_go
ugra_go_go_go_co
ugra_go_go_go_co
ugra_go_go_go_come_o
ugra_go_go_go_come_o
ugra_go_go_go_come_on_yes
ugra_go_go_go_come_on_yes_yes
ugra_go_go_go_come_on_yes_yes_a_bit
ugra_go_go_go_come_on_yes_yes_a_bit_mor
ugra_go_go_go_come_on_yes_yes_a_bit_more_jus
ugra_go_go_go_come_on_yes_yes_a_bit_more_just_a_
ugra_go_go_go_come_on_yes_yes_a_bit_more_just_a_
ugra_go_go_go_come_on_yes_yes_a_bit_more_just_a_lit
ugra_go_go_go_come_on_yes_yes_a_bit_more_just_a_lit
ugra_go_go_go_come_on_yes_yes_a_bit_more_just_a_lit
ugra_go_go_go_come_on_yes_yes_a_bit_more_just_a_little_c
ugra_go_go_go_come_on_yes_yes_a_bit_more_just_a_little_c87b
ugra_go_go_go_come_on_yes_yes_a_bit_more_just_a_little_c87bce6b
ugra_go_go_go_come_on_yes_yes_a_bit_more_just_a_little_c87bce6bbf6daa
ugra_go_go_go_come_on_yes_yes_a_bit_more_just_a_little_c87bce6bbf6daa2
ugra_go_go_go_come_on_yes_yes_a_bit_more_just_a_little_c87bce6bbf6daa2
```

This is actually an unintended solution. You can read the intended solution here: https://github.com/teamteamdev/ugractf-2022-quals/blob/master/tasks/xoxoracing/WRITEUP.md
