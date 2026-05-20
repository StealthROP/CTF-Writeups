# Liminal Signal - RE
> Flag: `JISSA{3nt1ty_kn0ws_y0ur_n4m3}`

## **1\. ANALYSIS**
Let's check first its `file` and `strings` of the the binary.
```
$file liminal_signal
liminal_signal: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=51c325ccf91aa82319b988f4b9a12a0519e6a3e4, for GNU/Linux 3.2.0, not stripped 
```
The binary is a stripped 64-bit ELF executable for Linux. Since it is stripped, symbol information like function names is removed, so analysis relies on disassembly and runtime inspection to understand its behavior.

```
$strings liminal_signal
GLIBC_2.34
__gmon_start__
PTE1
H=@@@
y0u_f0und_th3_w4ll
!i4.k.#
14j-)
#j/(
4n7i'Z
[90m
```

After checking its `strings` I found a unique string called `y0u_f0und_th3_w4ll` that might lead us to finding the flag. I will run the binary.

```
$./liminal_signal

+--------------------------------------------------+
|                                                  |
|   L I M I N A L   S I G N A L   v 0 . 0 . 1    |
|   [ CLASSIFIED ]  LEVEL-0 ACCESS REQUIRED       |
|                                                  |
+--------------------------------------------------+

You have wandered too far from the known world.
The hum of fluorescent lights is the only constant.
To escape, you must broadcast the correct frequency.

Enter frequency code: y0u_f0und_th3_w4ll

[+] SIGNAL LOCKED — frequency recognised.
A door opens in the yellow wallpaper.

Flag: JISSA{3nt1ty_kn0ws_y0ur_n4m3}
```
After running the binary, it asks for my input, and my input is `y0u_f0und_th3_w4ll` and it reveals the flag.

## **2\. LESSONS**
1.  It is important to always begin by inspecting the `file` (binary’s metadata) and `strings`, as they can quickly reveal useful information. Additionally, tools like `strace`, `objdump`, and `ltrace` should be used during initial analysis to better understand the program’s behavior and gather early insights.
