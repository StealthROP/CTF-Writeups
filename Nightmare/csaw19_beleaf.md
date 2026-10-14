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

