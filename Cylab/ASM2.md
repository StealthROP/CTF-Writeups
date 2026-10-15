# ASM2 — Reverse Engineering [HARD]

>Flag: 0x5e

### Details: 

What does asm2(0x4,0x1f) return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format.

### 1. Analysis

Cylab gave me this file and here is the contents of the **test.S**.

```
asm2:
	<+0>:	push   ebp
	<+1>:	mov    ebp,esp
	<+3>:	sub    esp,0x10
	<+6>:	mov    eax,DWORD PTR [ebp+0xc]       
	<+9>:	mov    DWORD PTR [ebp-0x4],eax	     
	<+12>:	mov    eax,DWORD PTR [ebp+0x8]	   
	<+15>:	mov    DWORD PTR [ebp-0x8],eax	   
	<+18>:	jmp    0x119c <asm2+31>
	<+20>:	add    DWORD PTR [ebp-0x4],0x1     
	<+24>:	add    DWORD PTR [ebp-0x8],0xf2	   
	<+31>:	cmp    DWORD PTR [ebp-0x8],0x3ae2     
	<+38>:	jle    0x1191 <asm2+20>		         
	<+40>:	mov    eax,DWORD PTR [ebp-0x4]
	<+43>:	leave
	<+44>:	ret
```

First thing's first, reading assembly starts _from right to left_.

Let's break down the important instructions, the first instruction of the assembly is this `<+6>:	mov    eax,DWORD PTR [ebp+0xc] ` means calculate the address first at `[ebp+0xc]` and `DWORD PTR` read **4** bytes into that address, lastly store it into the eax. 

Now, we are faced on what we called **dereferencing**. Dereferencing means accessing the data stored in that address and what we can do there is modify the data or read it. You may ask me "Why do we need to know dereferencing", well it's not enough to know which address you want to work with, you actually want to know which data is stored in the specific memory. `<+9>:	mov    DWORD PTR [ebp-0x4],eax` with this very own example, move the **4** bytes value from the `eax` and store it on address of `ebp-0x4`.

Moving on the next point, we now know `eax` is free of memory and available to store values again. 

```
	<+12>:	mov    eax,DWORD PTR [ebp+0x8]	   
	<+15>:	mov    DWORD PTR [ebp-0x8],eax
```

It's just like what I explained earlier, but its on the address of `[ebp+0x8]`.

`	<+18>:	jmp    0x119c <asm2+31>` tells us that we need to jump on `asm2+31`. 

`<+31>:	cmp    DWORD PTR [ebp-0x8],0x3ae2` compares the 4-byte value stored on `[ebp-0x8]` to **15074** (decimal value of **0x3ae2**). And jumps if the 4-byte value stored on address of `[ebp-0x8]` are less than **15074** to `asm+20`.

