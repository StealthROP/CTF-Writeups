# Keygen - Reverse Engineering

> Flag: Input Validation

### Details:

Simple Keygen 

### 1. Analysis

```Linux
file keygen_crackme
keygen_crackme: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a12eea3244e13be2e5cf90c77e5bb5edd89429bb,for GNU/Linux 3.2.0, not stripped
```

```Linux
strings keygen_crackme
/lib64/ld-linux-x86-64.so.2
puts
__isoc23_scanf
strlen
__libc_start_main
__cxa_finalize
printf
libc.so.6
GLIBC_2.38
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
Enter your name:
%49s
Enter your serial:
Correct! Access Granted.
Wrong serial. Access Denied.
```

### 2. Static Analysis

```C
undefined8 main(void)

{
  size_t name_length;
  ulong uVar1;
  int passwd_input;
  char name_input [56];
  int local_20;
  int i;
  
  i = 0;
  printf("Enter your name: ");
  __isoc23_scanf(&ptr_name,name_input);
  printf("Enter your serial: ");
  __isoc23_scanf(&ptr_passwd,&passwd_input);
  local_20 = 0;
  while( true ) {
    uVar1 = (ulong)local_20;
    name_length = strlen(name_input);
    if (name_length <= uVar1) break;
    i = i + name_input[local_20];
    local_20 = local_20 + 1;
  }
  i = i * 7 + 0x7b;
  if (i == passwd_input) {
    puts("Correct! Access Granted.");
  }
  else {
    puts("Wrong serial. Access Denied.");
  }
  return 0;
}
```

I've been transitioning to solving keygen challenges for a while now after solving countless XOR type challenges. This challenge introduces me to **keygen** challenges. 

```C
  while( true ) {
    uVar1 = (ulong)local_20;
    name_length = strlen(name_input);
    if (name_length <= uVar1) break;
    i = i + name_input[local_20];
    local_20 = local_20 + 1;
  }
```
`local_20` acts as the index/counter, while `i` acts as an accumulator. For each character in `name_input`, its ASCII value is added to `i`. Ryu's note: C automatically performs an arithmetic function if we use an arithmetic operation, in this case we perform an arithmetic function to **char** + **int** 

Visually its like this:

```
i = 0 + (int)'A';   // 0 + 65 = 65
i = 65 + (int)'B';  // 65 + 66 = 131
i = 131 + (int)'C'; // 131 + 67 = 198
//The characters are converted into int
```

```C
  i = i * 7 + 0x7b;
  if (i == passwd_input) {
    puts("Correct! Access Granted.");
  }
```

The above function changes the overall sum of my `i` by `  i = i * 7 + 0x7b` and lastly, it checks whether the resulting value of `i` matches the serial number I entered as `passwd_input`.

### 2. Solver Script

```Python
name_input = input()

i = 0
local_20 = 0

while len(name_input) > local_20:
    i = i + ord(name_input[local_20])
    local_20 = local_20 + 1

i = i * 7 + 0x7b

print(i)
```

This python solver asks for my input `name_input` and I reproduced the function of the main code we saw from earlier.

```Python
i = 0
local_20 = 0

while len(name_input) > local_20:
    i = i + ord(name_input[local_20]) #I used ord here to convert the name input to be a unicode.
    local_20 = local_20 + 1
```

And after the loop I added  `i = i * 7 + 0x7b`.

```Linux
python3 solver.py
hello
3847
```

### 3. Runtime

```Linux
./keygen_crackme
Enter your name: hello
Enter your serial: 3847
Correct! Access Granted.
```

### 4. Lessons
1. This was a tricky challenge for me because this type of challenge was unfamiliar to me. However, the experience helped me better understand how user input and password comparisons work.
