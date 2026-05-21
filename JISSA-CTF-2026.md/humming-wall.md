# Humming Wall — RE
> Flag: `JISSA{hum_1n_th3_w4ll}`

## 1. Analysis
```
$file humming_wall
humming_wall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d2cfeb8789f728c0a469afc9814c2c5a26730ee5, for GNU/Linux 3.2.0, stripped
```
Let's use `Ghidra` to analyze the binary.

Upon checking on `Ghidra`, I saw the main function. This binary accepts only `22` bytes of input `sVar2 == 0x16`. 

```
if (sVar2 == 0x16) {
  key = 0x23;
```

## 2. Logic
The logic of Xor is like this:

`input[i] ^ key == target[i]`

Where:

`target[i] → values stored in DAT_00102080.`

key starts at `0x23` (35) and increases by `7` each iteration.

And this is the logic of reversing the Xor key:

`input[i] = target[i] ^ key`
## 3. Scripts
```
Python
target = [
0x69, 0x63, 0x62, 0x6B, 0x7E, 0x3D, 0x25, 0x21,
0x36, 0x3D, 0x58, 0x1E, 0x28, 0x0A, 0xED, 0xBF,
0xCC, 0xED, 0x95, 0xC4, 0xC3, 0xCB
]

key = 0x23
result = ""

for byte in target:
result += chr(byte ^ key)
key += 7

print("Recovered input:", result)
```

This loop goes through each encrypted value in the `target` list one at a time using for `byte` in `target:`. For every `byte`, the code performs an `XOR` operation with the current `key` using `byte ^ key`, which decrypts the value because `XOR` can reverse the original encryption. After each character is checked, the key number becomes `7` bigger. So the first character uses one `key`, the second character uses a different `key`, the third uses another different `key`, and so on.

## 4. Lessons
1. I learned the logic behind decrypting XOR-based encryption. XOR is one of the most common encryption techniques used in reverse engineering challenges, especially in crackmes and CTFs. Understanding how XOR works and how to reverse it helps build a strong foundation for analyzing protected binaries and recovering hidden values. Learning this technique will also make it easier to progress into more intermediate and advanced reverse engineering challenges.
