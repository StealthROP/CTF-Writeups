# Beleaf - Reverse Engineering

> flag{we_beleaf_in_your_re_future}

### 1. Analysis

```
file beleaf
beleaf: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6d305eed7c9bebbaa60b67403a6c6f2b36de3ca4, stripped
```

```
strings beleaf
/lib64/ld-linux-x86-64.so.2
g@:lo+6
libc.so.6
exit
__isoc99_scanf
puts
__stack_chk_fail
printf
strlen
__cxa_finalize
__libc_start_main
GLIBC_2.7
GLIBC_2.4
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
5"
%$
%"
AWAVI
AUATL
[]A\A]A^A_
Enter the flag
>>>
Incorrect!
Correct!
;*3$"
GCC: (Ubuntu 7.4.0-1ubuntu1~18.04.1) 7.4.0
```

Pseudocode of main:

```C
undefined8 main(void)

{
  size_t input_len;
  long transformed_input;
  long in_FS_OFFSET;
  ulong i;
  char input_buf [136];
  long stack_canary;
  
  stack_canary = *(long *)(in_FS_OFFSET + 0x28);
  printf("Enter the flag\n>>> ");
  __isoc99_scanf(&DAT_00100a78,input_buf);
  input_len = strlen(input_buf);
  if (input_len < 0x21) {
    puts("Incorrect!");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  for (i = 0; i < input_len; i = i + 1) {
    transformed_input = transform_func((int)input_buf[i]);
    if (transformed_input != *(long *)(&desired_output + i * 8)) {
      puts("Incorrect!");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
  }
  puts("Correct!");
  if (stack_canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

Let's analyze the most important functions in the main.

```C
input_len = strlen(input_buf);
  if (input_len < 0x21) {
    puts("Incorrect!");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
```

`input_len` stores the length of our input buffer, then if our input length is less than **33** it will return as **Incorrect!** and exits the program.

```C
  if (stack_canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
```

This part of the code is literally what I learned the other day. It specifically checks if I have modified the original stack canary value. If it detects that the value has changed, the program will automatically terminate through `__stack_chk_fail()`. This is one of the protections a binary can have against stack buffer overflow attacks.

Contrary to what I said earlier, I noticed that this binary may be vulnerable to a stack buffer overflow. However, in this writeup, we will not pursue that route, as this challenge is not intended to be solved through that type of attack.

The initialization of `char input_buf[136];` allocates **136** bytes for the input buffer. Meanwhile, `if (input_len < 0x21)` checks whether our input length is less than **33** characters and rejects it if the condition is true. However, this check only enforces a minimum input length, and there is no visible check for the maximum input length. This leads to the possibility of a stack buffer overflow if the input exceeds the buffer's capacity and the `scanf()` format string does not limit the number of characters read.

```C
  for (i = 0; i < input_len; i = i + 1) {
    transformed_input = transform_func((int)input_buf[i]);
    if (transformed_input != *(long *)(&desired_output + i * 8)) {
      puts("Incorrect!");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
```

Our input length goes through a loop, and the index increments by **1** in each iteration. After that, the current character in our input buffer is typecast to an `int` and passed to `transform_func`, which performs some kind of transformation and stores the result in `transformed_input`.

Another thing is that I gained some great knowledge from [CyberSmash](https://www.youtube.com/@cybersmash3447). He explained that whenever I see something like `&desired_output + i * 8` or `i * 4`, I should pay attention to the memory offsets. This may indicate that the binary is accessing data at offsets of **8** bytes or **4** bytes, respectively, depending on the pointer type and the surrounding operations. For example, if each value occupies **8 bytes**, the next value starts **8** bytes after the previous one. However, we must also consider the pointer type to determine the actual offset.

`if (transformed_input != *(long *)(&desired_output + i * 8)) {` this part compares our transformed input to the bytes stored in the address of `&desired_output` and exits when it's incorrect.

Bytes on the `&desired_output`, as you can see it is **8** bytes away from the previous bytes:

```
                             desired_output                                  
        003014e0 01              ??         01h
        003014e1 00              ??         00h
        003014e2 00              ??         00h
        003014e3 00              ??         00h
        003014e4 00              ??         00h
        003014e5 00              ??         00h
        003014e6 00              ??         00h
        003014e7 00              ??         00h
        003014e8 09              ??         09h
        003014e9 00              ??         00h
        003014ea 00              ??         00h
        003014eb 00              ??         00h
        003014ec 00              ??         00h
        003014ed 00              ??         00h
        003014ee 00              ??         00h
        003014ef 00              ??         00h
        003014f0 11              ??         11h
```

### 2. Analyzing transformation function

Let's inspect the `transfom_func` function.

```C
long transform_func(char param_1)

{
  long local_10;
  
  local_10 = 0;
  while ((local_10 != -1 && ((int)param_1 != *(int *)(&lookup + local_10 * 4))))
  {
    if ((int)param_1 < *(int *)(&lookup + local_10 * 4)) {
      local_10 = local_10 * 2 + 1;
    }
    else if (*(int *)(&lookup + local_10 * 4) < (int)param_1) {
      local_10 = (local_10 + 1) * 2;
    }
  }
  return local_10;
}
```

The function initializes `local_10` to `0`, which serves as the index for searching the `lookup` array. The `while` loop checks whether the index is valid and whether the input character matches the current entry. If the character is smaller than the current value, the search moves to the left child using `local_10 * 2 + 1`. Otherwise, if it is greater, the search moves to the right child using `(local_10 + 1) * 2`. Each entry occupies 4 bytes, which explains the multiplication by `4` when accessing the array. The loop continues until a match is found or the index becomes `-1`. Finally, the function returns the index where the character was found, or `-1` if the search fails.

### 3. Solving the puzzle

After two solid days of figuring this thing out, I finally got the answer. there is `&desired_output` in which supposed to be the order of our flag, and get the right addresses and get the correct bytes from `&lookup`. The thing I'm so confused of is finding out of should I be using script to bruteforce this or manually solve this one (Ryu's note: I chose the manual solve as this was the part my brain gets and clicks some things).  

Now if you refer back to the section _2. Analyzing transformation function_, we can see that the first byte is 01, the next is 09h, and the next is 11h, and so on. I built a script that calculates the correct address. 

```Python
desired_output = [1, 9, 17, 39, 2, 0, 18, 3, 8, 18, 9, 18, 17, 1, 3, 19, 4, 3, 5, 21, 46, 10, 3, 10, 18, 3, 1, 46, 22, 46, 10, 18, 6]

stored = 0x00301020

for num in desired_output:
    addr = stored + (4 * num)
    print(hex(addr))
```

First I copied the hex bytes from the `&desired_output` and converted that into `decimal`. After that I copied the starting address from `&lookup` which is `0x00301020`, I then stored the bytes in array on `num` then I just copied this part `&lookup + local_10 * 4` and print it with an add ons of `hex` why hex? because if you just let it print, it will be converted into `int`, but we need an address and address starts with **0x** indicating we need it is made as hex values. 

Example run of script:
```
python -u "/home/equus/CTF/Nightmare/beginner-reversing/beleaf.py"
0x301024
0x301044
0x301064
0x3010bc
...
```

Cross referencing on the `&lookup`
```
        00301024 66              ??         66h    f
        00301044 6c              ??         6Ch    l
        00301064 61              ??         61h    a
        003010bc 67              ??         67h    g
        ...
```

This correctly corresponds to address produced on the script.

> Flag: flag{we_beleaf_in_your_re_future}

Running the program again.

```
./beleaf
Enter the flag
>>> flag{we_beleaf_in_your_re_future}
Correct!
```

### 4. Lessons
1. This challenge tired me out a lot because I didn't even understand why the binary search tree was there in the first place, lmfao. However, I gained a lot of knowledge, especially in understanding how to skip the extra bytes when analyzing the data and focus on the actual values I needed.

2. Persistence is the key, and sometimes going back to review the code is the answer. I suspected that I needed to brute-force the flag or solve it manually, but I couldn't figure out the right approach. In the end, I realized that I only needed to cross-reference the values from `desired_output` with the entries in `lookup` to reconstruct the flag.
