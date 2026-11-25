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

```
► 0x8049000 <_start>       mov    eax, 3                          EAX => 3
0x8049005 <_start+5>     mov    ebx, 0                          EBX => 0
0x804900a <_start+10>    mov    ecx, buffer                     ECX => 0x804a024 (buffer) ◂— 0
0x804900f <_start+15>    mov    edx, 0x14                       EDX => 0x14
0x8049014 <_start+20>    int    0x80 <SYS_read>
0x8049016 <_start+22>    mov    edx, eax
0x8049018 <_start+24>    mov    ecx, 0                          ECX => 0
0x804901d <_start+29>    mov    ebx, 0                          EBX => 0
0x8049022 <_loop>        mov    al, byte ptr [ecx + buffer]     AL, [buffer]
0x8049028 <_loop+6>      add    ebx, eax
0x804902a <_loop+8>      inc    ecx
```

This is the inside of `_start` function, let me break this down so you can read this even better.

```
► 0x8049000 <_start>       mov    eax, 3                          EAX => 3
0x8049005 <_start+5>     mov    ebx, 0                          EBX => 0
0x804900a <_start+10>    mov    ecx, buffer                     ECX => 0x804a024 (buffer) ◂— 0
0x804900f <_start+15>    mov    edx, 0x14                       EDX => 0x14
0x8049014 <_start+20>    int    0x80 <SYS_read>
```
This is what kinda intrigued me at first, there's an `int 0x80` instruction. Upon looking it up, I learned that it's a software interrupt used to invoke system calls in 32-bit Linux. And the `eax` contains **3** and it means `read` in the x86 Linux system calls [Official Documentation](https://syscall.sh/x86/). So in short its reading input into our buffer. 

The next would be the 3 lines after the first instruction, now we know the syscall, the other two is just an argument to the syscall. Conceptually this is like this in C.

```
read(0, buffer, 20);
```

Where the `EAX` is assigned to read, `EBX` is assigned to 0, `ECX` is assigned to buffer and lastly `EDX` is assigned to 20 which is the maximum bytes that the binary can read. I will just step in a few instructions until we get into instruction where the program asks for our input.

```
► 0x8049014 <_start+20>    int    0x80 <SYS_read>
fd: 0 (/dev/pts/1)
buf: 0x804a024 (buffer) ◂— 0
nbytes: 0x14
...
pwndbg> si
hello
```
After inputting **hello** the `EAX` now contains 6 (our input length) because `h e l l o \n` which is 6 bytes.

`0x8049016 <_start+22>    mov    edx, eax                        EDX => 6`

The `EDX` has now the same value as `EAX` which is our input length

```
0x8049022 <_loop>        mov    al, byte ptr [ecx + buffer]     AL, [buffer] => 0x68
0x8049028 <_loop+6>      add    ebx, eax                        EBX => 0x68 (0x0 + 0x68)
0x804902a <_loop+8>      inc    ecx                             ECX => 1
0x804902b <_loop+9>      cmp    ecx, edx                        1 - 6     EFLAGS => 0x293 [ CF pf AF zf SF IF df of ac ]
0x804902d <_loop+11>  ✔ jne    _loop                       <_loop>
```

Let me breakdown the following instructions above, the first instruction is reading one **byte** into our input and storing it into the `AL` (the lower part of the `EAX`). After that it adds the value of `EAX` into the `EBX` so the `EBX` contains `0x68` as shown in the calculation. Next its incrementing the value of `ECX` by 1 and comparing it to the value of `EDX` which is 6, and then loops if the two registers doesn't have the same value. The whole point of this is the program iterates to our input length and then adds the value of the buffer to the `EBX` register and lastly, it proceeds to the next instruction once the comparison fails.

```
► 0x804902f <_loop+13>    cmp    ebx, 0x988     0x21e - 0x988     EFLAGS => 0x287 [ CF PF af zf SF IF df of ac ]
0x8049035 <_loop+19>  ✘ jge    _win                        <_win>

0x8049037 <_loop+21>    jmp    _fail                       <_fail>
```

The next 3 instructions dictates whether we win or not. The first instruction compares the value of `0x988` to the value stored in `EBX`, the register contains only `0x21e` because that's the sum of the hex value of our input `hello`. It jumps to function `_win` if they are equal or greater than the compared value `0x988`. On the other hand, we have `_fail`, in this case, we fail because we didn't manage to meet the required value in the comparison.

## 2. Solution

Now that we know all the function, we will proceed to the solution part of this challenge. I used a **string to hex** website for this to identify which value holds the highest, in this case I found out the `z` holds `7A` in hex, so I spammed the `z` all the way to the maximum input length which is 20 and solved the challenge. The sum of 20 `z's` are `0x994`.

```
./chall1
zzzzzzzzzzzzzzzzzzzz
Congratz !
```

## 3. Learning
1. I just literally found out that `0x8049022 <_loop>        mov    al, byte ptr [ecx + buffer]     AL, [buffer]` is just reading one byte and I'm so genuinely impressed by this information, I will apply this information when solving for future CTF challenges.
2. `0x8049014 <_start+20>    int    0x80 <SYS_read>` this `int` instruction were new to me, and now that I know this is an system interrupt used by 32-bit Linux program. I also learned that `EAX` containing `0x3` identifies the read system call. I can navigate the binary more comfortably in the future with this newly gained information. 
