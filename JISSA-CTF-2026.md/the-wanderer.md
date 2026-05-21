# The Wanderer — RE
> Flag `JISSA{3ch0_0n_st4ck}`

## 1. Analysis

```
$file the_wanderer
the_wanderer: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ca517ad88e82bf3bf3460ce357d4bebc5b727b87, for GNU/Linux 3.2.0, stripped
```

```
$strings the_wanderer
/lib64/ld-linux-x86-64.so.2
mgUa
fgets
stdin
puts
strlen
strcspn
__libc_start_main
__cxa_finalize
memcmp
printf
libc.so.6
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
The corridor is listening.
Echo the phrase:
[ENTITY SATISFIED] The echo fades.
[STILL FOLLOWING] The echo remains behind you.
;*3$"
```

Upon checking the strings, I noticed that there is a `memcmp` function which means that I can use `gdb` [`pwndbg` to be specific] later for a faster flag retrieval.

I will check it on `Ghidra` first to identify the logic of the `memcmp` function.

```
    if (input_length == 0x14) {
      key = memcmp(local_98,local_b8,0x14);
      bVar4 = key == 0;
    }
```

`input_length` must be `0x14` or `20` in decimal, otherwise it will reject it, now that I got the `memcmp` logic and how it validates my `input_length`. I will now disassemble the binary by using the command `disass` or `disassemble` + `tab`.

```
pwndbg> disassemble
__cxa_finalize      fgets@got[plt]      memcmp@got[plt]     printf@got[plt]     puts@got[plt]       strcspn             strlen
__cxa_finalize@plt  fgets@plt           memcmp@plt          printf@plt          puts@plt            strcspn@got[plt]    strlen@got[plt]
fgets               memcmp              printf              puts                stdin               strcspn@plt         strlen@plt
```

After confirming that there is a `memcmp` function, I will break the `memcmp` function using the `break` or `b` command together with the `memcmp`.

```
pwndbg> break memcmp
Breakpoint 1 at 0x1070
```

Now that the breakpoint is set on the `memcmp` we can now run the program using `r` or `run`. It asks for my input and since the `input_length` must be `20`, our input length should be `20` too. 

```
pwndbg> run
Starting program: /home/equus/CTF/JISSA:SIGNAL_LOST/crow/04_TheWanderer/the_wanderer
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
The corridor is listening.
Echo the phrase: 12341234123412341234   ##this is 20 character length input
```

After I input `20` characters long, since I am using the `pwndbg` it automatically reveals the value inside the `rsi`, and the flag is right there. 

`RSI  0x7fffffffd670 ◂— 'JISSA{3ch0_0n_st4ck}'`

If you are using `gdb` vanilla, you can inspect the memory using the `x/s $rsi` command.

```
pwndbg> x/s $rsi
0x7fffffffd670: "JISSA{3ch0_0n_st4ck}"
```

## 2. Notes

Now why we use the `x/s $rsi` specifically and not `x/s $rdi`? If we inspect the current program state during the `memcmp` call, we can see that `rdi` contains our input, while `rsi` contains the reconstructed `flag` buffer. This happens because the program only calls `memcmp` when the input length is exactly `0x14` or `20`. Before the comparison occurs, the binary reconstructs the expected flag into `local_b8`.

```
RDI  0x7fffffffd690 ◂— '12341234123412341234'
RSI  0x7fffffffd670 ◂— 'JISSA{3ch0_0n_st4ck}'
```

## 3. Commands Explanation

`break` means setting a **breakpoint** in the program.
When execution reaches that location, the program pauses, allowing you to inspect registers, memory, variables, and the current program state. This helps analyze the behavior of the code during runtime.

`disassemble` means disassembling the binary and viewing the funcitons inside the binary, this is helpful for gaining a knowledge over the binary as it can give you lots of information.

`x/s $rsi` examines the memory pointed to by the `rsi` register and displays it as a string.

`run` running the program.

## 4 Lessons
1. Shoutout to Sakib, because it made me realize that whenever I see the memcmp in the rev challenges, I should always use `gdb` right away for faster flag retrieval.
2. Using `gdb` can enhance your reverse engineering skills, because you are not only stuck by doing static analysis `Ghidra`, you know how to do dynamic analysis also `gdb`.
