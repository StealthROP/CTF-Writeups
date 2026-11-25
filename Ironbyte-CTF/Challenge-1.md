# Challenge — Reverse Engineering

### I use Ironbyte's YouTube CTF challenges as references, but I write my own walkthroughs based on what I learned and understood. I don't just follow along; I dig deeper into the concepts and document my own findings. [Youtube Link](https://www.youtube.com/watch?v=1iptoUKXrcI&list=PL-A03qCBcinTiuCUtfhWGy1HMpnr0rOdh&index=9) 

## 1. Analysis
```
file chall1
chall1: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), statically linked, not stripped
```

```
strings chall1
Congratz !
You failed, try again!
expl.asm
winMessage
lenWinMessage
failMessage
lenFailMessage
buffer
_loop
_print
_fail
_win
_exit
__bss_start
_edata
_end
.symtab
.strtab
.shstrtab
.text
.data
```

And when running this challenge, it asks for our input and prints whether we win or not.

```
./chall1
hello
You failed, try again!
```

This time we failed the challenge after inputting the **hello**. This challenge relies heavily on solving it using **dynamic analysis**, with that in mind, I will use a `pwndbg` to analyze this challenge and uncover some areas. 

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x08049000  _start
0x08049022  _loop
0x08049039  _print
0x08049050  _fail
0x08049061  _win
0x08049072  _exit
```

In above, we see that we have several functions in this binary, I will break first on `_start` to see what's inside.
