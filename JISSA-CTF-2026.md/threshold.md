# Threshold — RE 
> Flag: `JISSA{n0cl1p_1nt0_th3_v01d}`
## 1. Analysis
Let's do the routine of checking the binary using `file` and `strings`.
```
$file threshold
threshold: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a48db6db21f3cc877b2d517c325167d9a84c87b0, for GNU/Linux 3.2.0, stripped
```
This is a binary that runs native on linux environment and is stripped. Since it is stripped, symbol information like function names is removed, so analysis relies on disassembly and runtime inspection to understand its behavior

```
Enter the exit code:
[SIGNAL LOST]
_____  _    _  _____    _____    _    _____  _  __  _____   ___   ___  __  __ _____
|_   _|| |  | || ____|  | __ )  / \  / ____|| |/ / |  __ \ / _ \ / _ \|  \/  / ____|
| |  | |__| || |__    |  _ \ / _ \| |     |   /  | |__) | | | | | | | \  / \____ \
| |  |  __  || __|    | |_) / ___ \ |___  |   \  |  _  /| |_| | |_| | |\/| |___  |
_| |_ | |  | || |____  |____/_/   \_\____| |_|\_\ |_| \_\ \___/ \___/|_|  |_|____/
|_____||_|  |_||_____|
[ANALOG TRANSMISSION
FREQUENCY 0x4E Hz]
WARNING: DO NOT LOOK DIRECTLY AT WALLS
You have noclipped out of reality.
Fluorescent hum. Wet carpet. Endless yellow halls.
To find the Threshold and escape, you must know the exit code.
[ENTITY_ALERT] Wrong code. The walls are closing in...
[SYSTEM] You will wander forever.
[THRESHOLD UNLOCKED] Reality subroutine restored.
You have escaped Level 0. Welcome back to reality.
Exit code accepted: %s
```
There is nothing that I found useful for solving this challenge, let's decompile it on Ghidra.

# 2\. Observations
> Note I renamed some of the variables.

I did deep checking on this pseudo-code and I found some leads, first it takes my `input` on exactly `0x1b = 27`.

`if (input_length == 0x1b)`

And XOR's my input by `0x4e = 78` and it compares the result to the address of the byte stored in `&target`. If it doesn't match, it will reject it instantly.

```
      do {
        if ((input[i] ^ 0x4e) != (&target)[i]) {
          puts("  [ENTITY_ALERT] Wrong code. The walls are closing in...");
          puts("  [SYSTEM] You will wander forever.");
          return 0;
        }
```

## 3. Scripts
Script for reversing the XOR encryption.
```
Python
target = [ 0x04, 0x07, 0x1d, 0x1d, 0x0f, 0x35, 0x20, 0x7e, 0x2d, 0x22, 0x7f, 0x3e, 
0x11, 0x7f, 0x20, 0x3a, 0x7e, 0x11, 0x3a, 0x26, 0x7d, 0x11, 0x38, 0x7e, 0x7f, 0x2a, 0x33 ]

key = 0x4e

flag = ''.join(chr(b ^ key) for b in target)

print(f"Result: {flag}")
```

First I get the bytes from the `target` array in memory and I get the key which is `0x4e`. After that I `XOR` each byte with the `key` to reverse the encryption and print it as the `flag`.

## 4. Lessons
1.  It would be a great help to know how to reverse XOR logic. Since XOR is reversible, applying the same key (`0x4e`) again reveals the original flag from the encoded `target` bytes.
