---
title: BRICS+ CTF Quals 2023 – FlagCMP
date: '2023-09-26'
draft: false
authors: ['thebadgod']
tags: ['BRICSCTF Quals 2023', 'Reverse', 'Wasm', 'VM']
summary: 'Wasm reversing; and pwning (kind of)'
---

# FlagCMP (Reverse, 1 solve)

> Thanks to modern technologies we finally have a crossplatform way to check that your flag is, indeed, correct.
>
> https://flagcmp-b8f9ceaf86d7846a.brics-ctf.ru/
>
> [Attachment & official solution](https://github.com/C4T-BuT-S4D/bricsctf-2023-stage1/tree/master/tasks/rev/flagcmp)

## First Analysis

We are given a zip file which contains a folder with docker container and sources for local testing. It contains the `app.js` backend, which basically just renders a template or invokes the `flagcmp.run` method if you give it some string.

Looking at the `impl.js` which defines said run method we see that it first passes the string to wasm, then calls the wasm `run` method and takes whatever we write to the first argument (as an address) as pointer/length to a string.

Generally there’s a lot of strings (which are just a `char*` and an `int` to store where and how long it is). There are also vectors, which are two pointers and some other various representations.

But well first of all we need to see the wasm code, I did so by using [nneoneo’s wasm plugin](https://github.com/nneonneo/ghidra-wasm-plugin). This immediatly tells us where the exported run method is, also the `set_flag` method, which is called inside `app.js` with the flag from the environment vars.

## Encoding the input

By looking how we call the run method we see the first argument is a return pointer, the second the char pointer and the last the size. We can see that we have a string constructor as first thing in the wasm implementation. It
uses the char pointer and size to construct the string. We then pass in the string (as two args) into the flag checking function. After that we free the string, move the result string from the check into the output and write the result pointer. (At least that’s what normal code generation would do, so I just assumed it was like that.)

Then in the check function we first construct a new datatype (might be a vector or an iterator), which is then moved and used as argument to another function. I just assumed that this is another string constructor, however it turns out that it might’ve been a `Program` constructor, compiling the `String` from befunge to bytecode.

<details>
  <summary>Spoiler alert</summary>

The whole thing is basically just a befunge VM.

</details>

Then we create a program buffer, where we insert the opcode `0xe`, then the instance we created earlier using our input (aka the compiled befunge), followed by another `0xe`. Then it inserts the flag checking portion (which is generated in the `set_flag` method, not really relevant how exactly it’s done, but basically it first has to create a constant for every char, for some reason it does not use befunges string mode here which would always be 3 opcodes but instead goes the extra mile to calculate the values using mathematical operations. Then for every char it inserts the constant generating code followed by a subtract and negate and finally a mult with whatever is at memory `0,0`. Effectively building an and gate out of all the negated differences).

Finally in the program it inserts opcoded `0x118` (push 1) and `0x12` (which outputs the popped value as an int). This output does not seem to be used. Then we insert some lazy static value (which seems to generate the constant 10) and output that as a character (so a newline).

Then the final bytecode is pushed which loads the value at `0,0` and outputs that as an int and terminates the program.

## Formatting the input

Now with the input in the program we need to convert the 1D string of bytecode into a 2D string of befunge. To do so we just create a 80 by 25 array and then set our position to `0,0` with deltax being 1. Then we start inserting our bytecode. At the last position in the first row, 79, we insert the opcode 10 to go to the next row, negate deltax and move a row down. There we first insert the opcode 7 or 8 (right / left) to change the direction accordingly. If we run out of space in the 80x25 we exit without output, which allows us to leak the flag length by just sending chars until we don’t get any more output and then do some math (basically just calculating how many operations are used if we don’t use any input, then do 2000-input-x to get the amount of instructions to encode the flag). Sadly because of the special encoding of the constants this yields a not entirely accurate result, as such I first got approximatly 58 characters.

Anyhow, after we fill the array we allocate a string, then pass in the array and the string into a constructor for the VM, which sets x,y to zero, moving direction to the right, sets the state to normal execution and the output string to the string we just allocated. The struct looks something like this:

```c
struct Instruction {
    unsigned char opcode;
    unsigned char extra_data; // for 0x18 and 0x19 (push ascii and push digit)
}; // size == 2

struct VM {
    Instruction *prog;
    string unused_but_probably_input_string;
    string output_string;
    random rng_instance; // used for the random opcode which makes us move in a random direction
    unsigned char x, y, dx, dy;
    unsigned char state;
}
```

Then we just call the step function, if that returns false we break or we stop if we hit 200,000 instructions executed. Else we just execute the bytecode. I have already mentioned a few opcodes, but here’s them all:

```
0  => a = pop(); b = pop(); push(b + a)
1  => a = pop(); b = pop(); push(b - a)
2  => a = pop(); b = pop(); push(b * a)
3  => a = pop(); b = pop(); if(a == 0) return 0; push(b / a)
4  => a = pop(); b = pop(); if(a == 0) return 0; push(b % a)
5  => a = pop(); push(!a)
6  => a = pop(); b = pop(); push(a < b)
7  => dx, dy =  1,  0
8  => dx, dy = -1,  0
9  => dx, dy =  0,  1
a  => dx, dy =  0, -1
b  => dx, dy = directions[randint(0, 3)]; // directions = [(1,0),(-1,0),(0,-1),(0,1)]
c  => dx, dy = (1 if pop() == 0 else -1), 0
d  => dx, dy = 0, (1 if pop() == 0 else -1)
e  => state = 1
f  => dup => a = pop(); push(a); push(a)
10 => swap => a = pop(); b = pop(); push(a); push(b)
11 => pop => pop()
12 => outputint => output += int(pop())
13 => outputchar => output += chr(pop())
14 => Bridge => skip next field
15 => Get => push(mem[(pop(), pop())]) # pops might be in wrong order
16 => Put => mem[(pop(), pop())] = pop() # pops might be in wrong order
17 => End => exit vm
18 => const Number => high byte contains value
19 => const Char => high byte contains value
```

Apart from the const char all the instructions are actually in order in a single string you can find using strings on the wasm binary

```
AddSubtractMultiplyDivideModuloNotGreaterRightLeftUpDownRandomHorizontalIfVerticalIfStringModeDupSwapPopOutputIntOutputCharBridgeGetPutEndNumber
```

Which obviously was found before I looked through all the opcode handlers...

After the execution is done we just check the output string. I don’t know the exact details, but it looks like it splits it at newlines, then uses the first to check the size of the second, but at this point I didn’t bother to see how this check specifically works, until I get the flag (or the program which encodes the flag) in the output string.

## The exploit

Well now we just have to somehow inject some befunge. Imagine wasting time trying to use non-ascii chars (which get filtered by the js) or by pushing out the flag checking part such that the last row will go into the string data and execute it as code (which does not work due to multiple reasons, easiest being that the input string is encoded using `0x18`).

Well as it turns out I already spoiled the exploit and well it’s actually really easy. We can just send the code we want. I eventually noticed that if we send `"@` we don’t get any output (by bruteforcing chars basically). Then looking at the bytecode generated revealed that it was indeed just executing the input as code.

So all we had to do was to get the program, we can just write a short for loop to get the program like this:

```py
from pwn import *
from requests import post

URL = "https://flagcmp-b8f9ceaf86d7846a.brics-ctf.ru"
#URL = "http://localhost:80"

prog = b""

for j in range(25):
    for i in range(80):
        payload = b'"' # escape
        a = i%9
        b = i//9
        payload += f"{b}9*{a}+".encode() # x coord
        a = j%9
        b = j//9
        payload += f"{b}9*{a}+".encode() # y coord

        payload += b'''1.52*,g,@'''      # don't know if necessary, but do the same thing as the original by printing 1 then newline and then the read char

        payload = payload.replace(b"+", b"%2b") # goddam url encode
        guess = payload + b"7"*2

        c = post(URL,
             headers={"Content-Type": "application/x-www-form-urlencoded"},
             data=b"guess="+guess
        ).content

        if b"result" in c:
            result = c.split(b"Comparison result: ")[1].split(b"</span>")[0]
            print(result)
            prog += result
            print(prog)
        else:
            exit(1)
```

This will slowly print the program row-by-row. Luckily for us this already deals with the encoding being zig-zag as we get the actual program. Unluckily this takes some time, however since I then need to interpret the program i figured i could just let it run and write the interpreter in the meantime. Like mentioned I assume that the first line is the length of the second line, however I didn’t confirm that, but if you want to optimize the befunge a bit feel free to.

Anyhow I finished this interpreter before I leaked the entire program:

```py
s = b'leaked prog'
# this goddamn html again
s = s.replace(b"&quot;", b"\"")
s = s.replace(b"&gt;", b">")
s = s.replace(b"&lt;", b"<")
# fill up to 2000 instructions
s = s + b" "*(2000-len(s))

"""
s = bytearray(s)
for r in range(2, 25, 2):
    for i in range(40):
        s[80*r+i], s[80*r+79-i] = s[80*r+79-i],s[80*r+i]
"""
s = s.decode()

ss = s[:]
while ss:
    print(ss[:80])
    ss = ss[80:]
print(s)

stack = [0]*80
str_mode = False

x = 24
y = 0
dx = 1
dy = 0
flag = b""
prev = -1
while s:
    o = s[y*80+x]
    print(x,y,o)

    if str_mode:
        if o == '"': str_mode = False
        else: stack.append(ord(o))
        continue

    if o in "0123456789":stack.append(int(o))
    else:
        match o:
            case '"':str_mode = True
            case '*':
                a = stack.pop()
                b = stack.pop()
                stack.append(b * a)
            case '+':
                a = stack.pop()
                b = stack.pop()
                stack.append(b + a)
            case '/':
                a = stack.pop()
                b = stack.pop()
                stack.append(b // a)
            case '-':
                a = stack.pop()
                b = stack.pop()
                stack.append(b - a)
                prev = p8(a)
            case ".":stack.pop()
            case ",":stack.pop()
            case "g":
                flag += prev
                print(flag[::-1])
                stack.pop()
                stack.pop()
                stack.append(0)
            case "p":
                stack.pop()
                stack.pop()
                stack.pop()
            case ":":
                a = stack.pop()
                stack.append(a)
                stack.append(a)
            case "!":
                stack.append(0 if stack.pop() else 1)
            case "v":
                dx = 0
                dy = 1
            case "<":
                dx = -1
                dy = 0
            case ">":
                dx = 1
                dy = 0
            case _:
                print("unimplemented:", o)
                exit(1)
    x += dx
    y += dy
```

Which was enough to "execute" the program and give us the flag `brics+{c3rtif1ed_es0l4ng_expl0it_d3vel0per_c65596e73d72cac7}`.
