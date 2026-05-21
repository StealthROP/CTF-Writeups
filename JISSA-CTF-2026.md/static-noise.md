# Static Noise — RE
> Flag `JISSA{st4t1c_n01s3}`

# 1. Analysis

```
$file static_noise
static_noise: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=99355fd9f5a835f6a9edd3be420f663f2d089d82, for GNU/Linux 3.2.0, stripped
```
```
$strings static_noise
/lib64/ld-linux-x86-64.so.2
mgUa
fgets
stdin
puts
strlen
strcspn
__libc_start_main
__cxa_finalize
printf
libc.so.6
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
Level C-3 broadcast lock
Broadcast response:
[NOISE ONLY] The screen keeps flickering.
[SIGNAL LOCKED] The static clears.
;*3$"
GCC: (Debian 14.2.0-19) 14.2.0
```

Let's use Ghidra to analyze the binary.

```
    if (input_length == 0x13) {
      key = 0x55;
      i = 0;
      checksum_state = 0x41;
      while (checksum_state = checksum_state * 0x1d + 0x11 + (int)i,
            (byte)(user_input[i] ^ key ^ (byte)checksum_state) == (&target)[i]) {
        i = i + 1;
        key = key + 0xd;
        if (i == 0x13) {
          puts("[SIGNAL LOCKED] The static clears.");
          return 0;
        }
```
Above is the obfuscation logic of the binary, first my input length should be `0x13` or `19`.

`checksum_state = checksum_state * 0x1d + 0x11 + (int)i`

The `checksum_state` changes every iteration.

`(byte)(user_input[i] ^ key ^ (byte)checksum_state)` 

This is `XOR`-based obfuscation / stream-like transformation. However, if you notice the `(byte)checksum_state` has a `byte` embedded with it. In easier terms it uses a low-byte truncation meaning in the hex of `0x12345678` only the value of `0x78` will be fetched. 

`(&target)[i]`

Array indexing of the expected byte at position `i`.

## 2. Script and Explanation

```
Python
target = [ 0x71, 0xa3, 0x47, 0x2c, 0xa4, 0xbf, 0xb1, 0xd1, 0xf3, 0x52, 0x31, 0xf0, 0x36, 0xc6, 0xe6, 0x00, 0x90, 0x91, 0x31 ]

key = 0x55
checksum_state = 0x41

output = []

for i in range(0x13):  # 19 bytes
checksum_state = checksum_state * 0x1d + 0x11 + i
mask = checksum_state & 0xFF  # low byte only

original_byte = target[i] ^ key ^ mask
output.append(original_byte)

key = (key + 0x0D) & 0xFF  # keep it in byte range

print("".join(chr(b) for b in output))
```

First, I copied the `checksum_state` logic so I can keep track of its state. 

`mask = checksum_state & 0xFF  # low byte only`

It fetches the low-byte only. 

`original_byte = target[i] ^ key ^ mask`

The `mask` is derived from the low-byte of `checksum_state` and is used in the `XOR` operation.

`key = (key + 0x0D) & 0xFF  # keep it in byte range`

The part `& 0xFF` is what forces this behavior. It keeps only the last `8 bits` of the number, which is the same as doing “mod 256”. So when key becomes bigger than `255`, it automatically loops back into the `0–255` range. This is important because the program uses key in `XOR` operations with bytes, and `XOR` only makes sense correctly if both values stay within that same `0–255` range. Without this, `key` would grow too **large** and your decryption would stop matching the original program after a few characters.

## 3. Lessons
1. This challenge introduced me to **low-byte truncation**, where only the least significant byte of a hexadecimal value is used.
2. It also highlighted the importance of `0xFF` in deobfuscation, since it keeps values constrained to the 0–255 byte range during the process.
