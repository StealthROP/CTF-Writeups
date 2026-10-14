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

After two solid days of figuring this thing out, I finally got the answer. there is `&desired_output` in which supposed to be the order of our flag, and get the right addresses from `&lookup`. The thing I'm so confused of is finding out of should I be using script to bruteforce this or manually solve this one (Ryu's note: I chose the manual solve as this was the part my brain gets and clicks some things).  
