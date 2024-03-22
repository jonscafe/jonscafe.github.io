---
title: BSidesTLV 2022 CTF – SEV
date: '2022-07-01'
draft: false
authors: ['radewoosh']
tags: ['BSidesTLV 2022', 'Crypto', 'ECC', 'Elliptic Curve']
summary: 'Steal secret key and get the flag.'
---

## SEV (Crypto, 500)

> Welcome to our secure confessions service. We got an annoymous tip that our customers' sins can be recovered. Please find what sin is hiding in our KE implementation.
>
> `nc sev.ctf.bsidestlv.com 3535`
>
> Attachments: [code.zip](https://ctf22.bsidestlv.com/files/59d7738c2641c85e2b05e5cbc1893086/code.zip?token=eyJ1c2VyX2lkIjoyODYsInRlYW1faWQiOjExNiwiZmlsZV9pZCI6OH0.Yr3wug.0zgiqGqtbCh9M-6eUY_DlcJQY5o) [session.pcap](https://ctf22.bsidestlv.com/files/9192622117171fc134bf3afd34cb31f1/session.pcap?token=eyJ1c2VyX2lkIjoyODYsInRlYW1faWQiOjExNiwiZmlsZV9pZCI6OX0.Yr3wug.WVniIuq_rSXKw3u0MKXZf3zZ6jc)

`session.pcap` file contains an history of a communication between a client and the server:

<pre>
<span style={{color: "#EF9A9A"}}>Dg7ADYs5Yu71LzYF/AAJCCFrNT9LCZEKNOb4aYcRGbsqJeaCN4/Sv4Kqqcd5E46kiEKcd84pwJ+sJrfkO7ZCTkUzIiV1AvVbOSMrv9fHRHi8sJDXy6IIYeRbKrV8rQEA
Provide PoW to be forgiven: sha256(secret || nonce) == tag
Where len(secret) is 4. nonce and tag are provided as data:
ejBLSmF5cGpJTllyUWdFbQ==|A8zoQrrWIY8khG8NFXHBFW/IOz2v9fN0TtkdH3O7Um0=</span>
<span style={{color: "#90CAF9"}}>amVQaw==
Ag==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABFXpIhjPhJvBHkYjZsJwQvRH2tCYB8gyfsSxUweg7IWheZXc2UvB4ELB918rjFfw4=|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABX0G/QAGJkGhwZMS71XSTa1gCHNiPHisAytIz2RMKl8EiR6ViMcZDFz3zbJyl3J4Y=</span>
<span style={{color: "#EF9A9A"}}>ETtQGKvbgQi+2XLWNBT0iuUJrLW7m4Bygb5triaWj3Momg5LF4GNuH/H/fxWHBZXjmIiySoSXo/IdRlkX73vuWNhiUjmOUsFZxNXLP4B2e3gplFqkjYNhn2cFAp03TTz|4+qRIXALaaZCk7yq5iQEQyt/ChqLuWpizc/0hkCJzuo=</span>
<span style={{color: "#90CAF9"}}>DovsN9mEHsSZ/yChmtzfRBDw6SXjwSSPTSWSgsa4wJ9GIEmcF8DNlSoxi5l5H6ZrQTt+pweN472ShhMlTQEw328EXaLbmt0C62CfCB9dAAG7fqE=|ViSMR4tOyjxQsoP4klviilAOFZPFTGVOvmtfkqsQcok=</span>
<span style={{color: "#EF9A9A"}}>You are forgiven for sin confessed having sha256 digest: b68c2d5ababa5080b4105bf2fcde89060f92ff6512d5e321a2b102172d9fbc42</span>
<span style={{color: "#90CAF9"}}>JmNyidFvtENv3LsvJgVl7D9G7Z+445yYRoDC6I8wSB29kpuZJGo92jGglry2ab61O8BGGnu0rw==|I8ppGR6Kt75CUhzxWCaOGXXg54FCTVFSLfw+qUBkYOo=</span>
<span style={{color: "#EF9A9A"}}>You are forgiven for sin confessed having sha256 digest: d05c56b4692ccd47063fc6d12a3c00ff8ab332c7fb91a797a0862cb0e63e6826</span>
<span style={{color: "#90CAF9"}}>wsMeqBQZdU5mf+vdhVYZ+pccL6T3/Rej8w1j++69iXsnpa5XjBkuraVDwA8FEaWyLrby8K4UmBeYvoekl9xDDXtjT1YOnBomuA==|5EFItaA9aE/sKdPqmOWehB+YuzSY8ylcM4sh9QscIwY=</span>
<span style={{color: "#EF9A9A"}}>You are forgiven for sin confessed having sha256 digest: b07a7bc955aff2c8e58b7a4747b7519fa0d4a306648cc81ca79bd5ed724b12e4</span>
<span style={{color: "#90CAF9"}}>JWOv0CMe/IWIeiI+HZq8CxI58nVBZiYHdW0X3n9D79QCqTmrV3tSTAlIPMUJ8yRSoevt4+ZHH8UPkHW0ew+F|JOXncbnsOIQG0qAUbNz5YEL+i6snXmDH2Wsg6Nr8tT0=</span>
<span style={{color: "#EF9A9A"}}>You are forgiven for sin confessed having sha256 digest: 7ca4d4086a677a14adcce62cc45fc78ea60e787dbbb7b307c3e8ff5f4fa8fb09</span>
<span style={{color: "#90CAF9"}}>DaKaH+g0YQFVSoc20sYgkEViShc6IFUpy5sWnZ6wLTVgnzfzGzQkdJ4Tmk62qr2wtn/2kj0RuRatsh3Pwq3AmU51sSEhXLqIULLnpvwJl/z0|gFXeRQw/TqTiffeT7Vrgt5moNZRtAnqjPnuSJmExsSs=</span>
<span style={{color: "#EF9A9A"}}>You are forgiven for sin confessed having sha256 digest: 9d8b988dea424160cf3089a8a87aa4a1313da16619d5d5c0ace08d649e2e5310</span>
<span style={{color: "#90CAF9"}}>AFQyWZ0EyEC2fzGEEyXjfQhRlA==|BP7opu0HHysi94IXc4Shw+mWFowGrz7L1hQv4SJxqrc=</span>
<span style={{color: "#EF9A9A"}}>You are forgiven for sin confessed having sha256 digest: a8e4843b9ff167627f87c431151680675d74f14b12a8c12a6038c669588ee0c3</span>
<span style={{color: "#90CAF9"}}>/SMw0AfL7BEPQIZgsT2Su3voQ6GWAIrRDuwehAk8n05+rR+8Ng0cq5YMX44qpXtZ1m2OJnUpBb1LjA==|VTCuEaanvKN/5klaQEGQ3cdSGei65hroORxBgpUSQnw=</span>
<span style={{color: "#EF9A9A"}}>You are forgiven for sin confessed having sha256 digest: 6a4cde95ef46d6d184fd2c2a9be522acd02edb229d296c5ffbd292f68e389024</span>
</pre>

We can guess, that the flag is in client’s confession, so our job is to decrypt it. To do this we will try to steal server’s secret key, which is constant and will be denoted here by $s_k$.

To communicate we can choose one of two curves, `p256` and `p384`, for which there are two primes, let’s call them $p_1$ and $p_2$. After reading `main.py` we realize that if we choose the first (smaller) curve, the point sent to the server (let’s call it $P$) must lie `p256`, but instead of $p_1$, server will use $p_2$ to calculate the shared key. This means that it won’t actually use `p384`, but some other curve (with the same prime number) and the shared key (let’s call it $S$) will be equal to $P \times s_k$.

First of all, we need to know this `shared_key`. Let’s look at the code:

```py
def send_debug(ecdh, ctx):
    res = ecdh.public_key.pubkey.point * ecdh.private_key.privkey.secret_multiplier
    io.writeData(*ctx.tx_encrypt(res.to_bytes()))
    ctx.tx_ctx.CTR.val = 0
```

```py
    id = sha256(ecdh.public_key.to_string()).digest()
    if debug:
        send_debug(ecdh, ctx)
    try:
        io.writeData(*ctx.tx_encrypt(f"Welcome your pub fingerprint is {id.hex()}".encode('latin1')))
```

Server sends to us two encrypted lines. One contains the shared key, and the other contains a welcome message, which we can know, as it contains a SHA256 of $P$ which is chosen by us. These two lines happen to have the exact same length and it turns out, that this encryption is just xoring both of the lines with the same sequence of bytes. So, if we take the xor of these two lines and the welcoming message, we are left with the shared key.

Great, as $S = P \times s_k$, we just have to solve the discrete logarithm problem. But that’s hard... So, what are the differences between standard version of this problem and the presented one? Firstly, we won’t be solving it on any specified curve (as `p384` for example), as our point comes from `p256` and the calculations will be performed modulo $p_2$. Secondly, we can send many points to the server and get many equations, with the same prime number, but on different curves (generated by the points of our choice).

Here we’ll make use of the algorithm to calculate the order of a point on elliptic curve. So, let’s look at the value of $\text{ord}(P)$ and let’s try to find its small divisor. Here by “small” we mean an iterable one, so let’s say smaller than a million. If there is such a divisor, and there is high probability that there is, then denote it by $d$ and instead of looking at points $P$ and $S$, look at points $P \times {\text{ord}(P) \over d}$ and $S \times {\text{ord}(P) \over d}$. For them we can solve the discrete logarithm problem easily, as the order of $P \times {\text{ord}(P) \over d}$ is small.

So, we have an equation $P \times {\text{ord}(P) \over d} \times k = S \times {\text{ord}(P) \over d}$. Does it tell the exact value of $s_k$? Of course no, but it tells us about the remainder of dividing $s_k$ by $d$. That actually gives us the whole solution, as if we collect enough congruences, we’ll be able to use Chinese remainder theorem to get the exact value of $s_k$.

With everything thought out, we can start the attack. To calculate the order of curves we can use sage:

```py
from sage.misc.prandom import randrange
from tqdm import tqdm
import signal
class p384:
    p = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319
    b = 27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575
    a = -3
    Gx = int("AA87CA22 BE8B0537 8EB1C71E F320AD74 6E1D3B62 8BA79B9859F741E0 82542A38 5502F25D BF55296C 3A545E38 72760AB7".replace(" ", ""), 16)
    Gy = int("3617DE4A 96262C6F 5D9E98BF 9292DC29 F8F41DBD 289A147CE9DA3113 B5F0B8C0 0A60B1CE 1D7E819D 7A431D7C 90EA0E5F".replace(" ", ""), 16)

class p256:
    p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
    b = int("5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F63BCE3C3E 27D2604B".replace(" ", ""), 16)
    a = -3
    Gx = int("6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0F4A13945 D898C296".replace(" ", ""), 16)
    Gy = int("4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECECBB64068 37BF51F5".replace(" ", ""), 16)


K = GF(p256.p)
P256 = EllipticCurve(K, [p256.a, p256.b])

while True:
    while True:
        try:
            P = P256.lift_x(K.random_element())
            break
        except Exception as e:
            continue

    x, y = map(int, P.xy())
    b_ = (y * y - x ^ 3 + 3 * x) % p384.p
    ec = EllipticCurve(GF(p384.p), [-3, b_])

    print("Calculating EC order")
    o = ec.order()
    print(x)
    print(y)
    print(o)
    print()
```

We had small problems with sage getting stuck, but we managed to collect 58 various points together with their order. We saved them in a file:

```bash
89936635954347721082291662199830953644415701978674159588335797948725963360121
75603778932495181759544986564297344224164574459444354228241781117643409370328
39402006196394479212279040100143613805079739270465446667945677458609027261747300550436222500290897901412646071140521

94669244813001974863196163432068054052897736338944823404184997020382981219790
63246684792990410882044657474118318613402239831513202414041221302452475231147
39402006196394479212279040100143613805079739270465446667953428258142871094028478103699443071551088605265882646853173

30789509188003919664641197040026779665452432414110328926013251738811451876528
59959100322647307194286668737312561534119906525946272810561021041294062507683
39402006196394479212279040100143613805079739270465446667958033666035318438249614543376887412317906233830648430493355
...
```

Now we are ready to read these curves from the file and talk with the server:

```python
curves = []

for i in range(58):
	x = int(input())
	y = int(input())
	o = int(input())
	input()
	curves.append((x, y, o))

tries = []
for a in digits + ascii_letters:
	for b in digits + ascii_letters:
		for c in digits + ascii_letters:
			for d in digits + ascii_letters:
				tries.append((a + b + c + d).encode())

def xorit(a, b):
	return bytes(x^y for x,y in zip(a, b))

def calc_sol(i):
	conn = remote('sev.ctf.bsidestlv.com', 3535)

	conn.recvline()
	conn.recvline()
	conn.recvline()
	take = conn.recvline()
	take = Data.SplitData(take)
	prover = PoW()
	prover.nonce = take[0]
	for j in range(len(tries)):
		trying = tries[j]
		if prover.validate(trying, take[1]):
			conn.send(b64encode(trying) + b'\n')
			break
	conn.send(Data.JoinData((1).to_bytes(1, byteorder='big'), i[0].to_bytes(80, byteorder='big'), i[1].to_bytes(80, byteorder='big')) + b'\n')
	a = conn.recvline()
	b = conn.recvline()
	a = Data.SplitData(a)
	b = Data.SplitData(b)
	a = a[0]
	b = b[0]
	id = sha256(PointJacobi(curve_map[2], i[0], i[1], 1).to_bytes('raw')).digest()
	c = f"Welcome your pub fingerprint is {id.hex()}".encode('latin1')
	shared = xorit(a, xorit(b, c))

	x = string_to_number(shared[:48])
	y = string_to_number(shared[48:])
	conn.close()
	return(PointJacobi(curve_map[2], i[0], i[1], 1), PointJacobi(curve_map[2], x, y, 1), i[2])

pool = ThreadPool(4)
sols = pool.map(calc_sol, curves)

def is_prime(v):
	if v <= 1:
		return False
	x = 2
	while x * x <= v:
		if v % x == 0:
			return False
		x += 1
	return True

prod = 1
w = 1
r = 0
while True:
	w += 1
	if not is_prime(w):
		continue
	take = None
	for i in sols:
		if i[2] % w == 0:
			take = i
	if take is None:
		continue
	print(w, 'will work')
	a = take[0] * (take[2] // w)
	b = take[1] * (take[2] // w)
	u = a
	for j in range(1, w + 1):
		if u == b:
			should = j
			print(j, w)
			while (r % w) != (j % w):
				r += prod
			break
		u = u + a
	prod *= w
	print('R is', r)
	print('Product is', prod)
```

This gives us the desired value of $s_k$:

```
18430131452148989837577882252868373891854598671610031055403934843354901730409281854175550384893659770012714739087985
```

Using the point sent by the client in `session.pcap` to the server, we can calculate their shared key and use it to decrypt the confessions:

```py
x = 10676930506344505873343842825136193063086736081417640908491244252777962392401494994145689818929842945737119139987214
y = 13515843335184786939328473707652274608813326314510139953701071845110611907135279260510778339890982259161016709883782
prv_key = Point(curve_map[2], x, y)

shared = prv_key * 18430131452148989837577882252868373891854598671610031055403934843354901730409281854175550384893659770012714739087985
password = number_to_string(shared.x(), curve_map[2].p())

ctx = session_context(password, Role.Responder)

msgs = [b'DovsN9mEHsSZ/yChmtzfRBDw6SXjwSSPTSWSgsa4wJ9GIEmcF8DNlSoxi5l5H6ZrQTt+pweN472ShhMlTQEw328EXaLbmt0C62CfCB9dAAG7fqE=|ViSMR4tOyjxQsoP4klviilAOFZPFTGVOvmtfkqsQcok=',
		b'JmNyidFvtENv3LsvJgVl7D9G7Z+445yYRoDC6I8wSB29kpuZJGo92jGglry2ab61O8BGGnu0rw==|I8ppGR6Kt75CUhzxWCaOGXXg54FCTVFSLfw+qUBkYOo=',
		b'wsMeqBQZdU5mf+vdhVYZ+pccL6T3/Rej8w1j++69iXsnpa5XjBkuraVDwA8FEaWyLrby8K4UmBeYvoekl9xDDXtjT1YOnBomuA==|5EFItaA9aE/sKdPqmOWehB+YuzSY8ylcM4sh9QscIwY=',
		b'JWOv0CMe/IWIeiI+HZq8CxI58nVBZiYHdW0X3n9D79QCqTmrV3tSTAlIPMUJ8yRSoevt4+ZHH8UPkHW0ew+F|JOXncbnsOIQG0qAUbNz5YEL+i6snXmDH2Wsg6Nr8tT0=',
		b'DaKaH+g0YQFVSoc20sYgkEViShc6IFUpy5sWnZ6wLTVgnzfzGzQkdJ4Tmk62qr2wtn/2kj0RuRatsh3Pwq3AmU51sSEhXLqIULLnpvwJl/z0|gFXeRQw/TqTiffeT7Vrgt5moNZRtAnqjPnuSJmExsSs=',
		b'AFQyWZ0EyEC2fzGEEyXjfQhRlA==|BP7opu0HHysi94IXc4Shw+mWFowGrz7L1hQv4SJxqrc=',
		b'/SMw0AfL7BEPQIZgsT2Su3voQ6GWAIrRDuwehAk8n05+rR+8Ng0cq5YMX44qpXtZ1m2OJnUpBb1LjA==|VTCuEaanvKN/5klaQEGQ3cdSGei65hroORxBgpUSQnw=']
for msg in msgs:
	msg = Data.SplitData(msg)
	print(ctx.rx_decrypt(*msg))
```

> Once, I encrypted penguins using ECB. I can still hear them screaming in my dreams.
> I find Lady LFSR's irreducible polynomial irresistible.
> Reusing primes to accelerate private key generation is my dirty pleasure.
> Hardcoding passwords is one of my preferred pastime activities.
> My clients' passwords are always stored encrypted with military grade encryption.
> MD5 is my best bud.
> `BSidesTLV2022{b3wear_7h3_1nv4lid_curv3_0r_l00s3_y0ur_51ns}`

## Flag

```bash
BSidesTLV2022{b3wear_7h3_1nv4lid_curv3_0r_l00s3_y0ur_51ns}
```
