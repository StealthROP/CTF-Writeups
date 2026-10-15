# Exatlon — Reversing

> Flag: HTB{l3g1c3l_sh1ft_l3ft_1nsr3ct1on!!}


### Details: 

Can you find the password?

## 1. Analysis

```
file exatlon_v1
exatlon_v1: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, no section header
```
What is **section header?** A section header is the metadata of a binary file (ELF or PE) that contains useful information when performing an analysis.

It says here that there is `no section header` which makes the binary harder to analyze. I will check the binary file using `strings` to gain more information.

```
strings exatlon_v1
UPX!<
!E&8
C}Rn
_[a/J(kb<

--- Jumped to the end ---

'.bss
$$!
]<'B
vQ0
UPX!
UPX!
```

The `UPX` is shown multiple times. This hints me that the binary file must be packed on [`UPX`](https://github.com/upx/upx).

### Unpacking the binary file

```
upx -d exatlon_v1 -o exatlon_v1_unpaxed
Ultimate Packer for eXecutables
Copyright (C) 1996 - 2024
UPX 4.2.4       Markus Oberhumer, Laszlo Molnar & John Reiser    May 9th 2024

File size         Ratio      Format      Name
--------------------   ------   -----------   -----------
2210504 <-    709524   32.10%   linux/amd64   exatlon_v1_unpaxed

Unpacked 1 file.
```

I will perform an analysis on **Ghidra** to learn how the binary works now that it is unpacked. 

```

undefined4 main(void)

{
  bool bVar1;
  ostream *poVar2;
  undefined4 unaff_R12D;
  string local_58 [32];
  string local_38 [32];
  
  do {
    std::operator<<((ostream *)&std::cout,"\n");
    std::operator<<((ostream *)&std::cout,&DAT_0054b018);
    std::operator<<((ostream *)&std::cout,&DAT_0054b0d8);
    sleep(1);
    std::operator<<((ostream *)&std::cout,&DAT_0054b1a8);
    std::operator<<((ostream *)&std::cout,&DAT_0054b260);
    sleep(1);
    std::operator<<((ostream *)&std::cout,&DAT_0054b320);
    sleep(1);
    std::operator<<((ostream *)&std::cout,&DAT_0054b400);
    sleep(1);
    std::__cxx11::string::string(local_58);
                    /* try { // try from 00404cfe to 00404dce has its
                       CatchHandler @ 00404def */
    std::operator<<((ostream *)&std::cout,"[+] Enter Exatlon Password  : ");
    std::operator>>((istream *)&std::cin,local_58);
    exatlon(local_38);
    bVar1 = std::operator==(local_38,
                            "1152 1344 1056 1968 1728 816 1648 784 1584 816 1728  1520 1840 1664 784 1632 1856 1520 1728 816 1632 185 6 1520 784 1760 1840 1824 816 1584 1856 784 1776 176 0 528 528 2000 "
                           );
    std::__cxx11::string::~string(local_38);
    if (bVar1) {
      poVar2 = std::operator<<((ostream *)&std::cout,"[+] Looks Good ^_^ \n\n\n"
                              );
      std::ostream::operator<<(poVar2,std::endl<>);
      unaff_R12D = 0;
      bVar1 = false;
    }
    else {
      bVar1 = std::operator==(local_58,"q");
      if (bVar1) {
        unaff_R12D = 0;
        bVar1 = false;
      }
      else {
        poVar2 = std::operator<<((ostream *)&std::cout,"[-] ;(\n");
        std::ostream::operator<<(poVar2,std::endl<>);
        bVar1 = true;
      }
    }
    std::__cxx11::string::~string(local_58);
  } while (bVar1);
  return unaff_R12D;
}
```

```
do {
    std::operator<<((ostream *)&std::cout,"\n");
    std::operator<<((ostream *)&std::cout,&DAT_0054b018);
    std::operator<<((ostream *)&std::cout,&DAT_0054b0d8);
    sleep(1);
    std::operator<<((ostream *)&std::cout,&DAT_0054b1a8);
    std::operator<<((ostream *)&std::cout,&DAT_0054b260);
    sleep(1);
    std::operator<<((ostream *)&std::cout,&DAT_0054b320);
    sleep(1);
    std::operator<<((ostream *)&std::cout,&DAT_0054b400);
    sleep(1);
```

This part of the code prints the `EXATLON_V1` repeatedly until you get the correct password.

```
./exatlon_v1_unpacked

███████╗██╗  ██╗ █████╗ ████████╗██╗      ██████╗ ███╗   ██╗       ██╗   ██╗ ██╗
██╔════╝╚██╗██╔╝██╔══██╗╚══██╔══╝██║     ██╔═══██╗████╗  ██║       ██║   ██║███║
█████╗   ╚███╔╝ ███████║   ██║   ██║     ██║   ██║██╔██╗ ██║       ██║   ██║╚██║
██╔══╝   ██╔██╗ ██╔══██║   ██║   ██║     ██║   ██║██║╚██╗██║       ╚██╗ ██╔╝ ██║
███████╗██╔╝ ██╗██║  ██║   ██║   ███████╗╚██████╔╝██║ ╚████║███████╗╚████╔╝  ██║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═══╝   ╚═╝


[+] Enter Exatlon Password  :
```

```
    std::operator<<((ostream *)&std::cout,"[+] Enter Exatlon Password  : ");
    std::operator>>((istream *)&std::cin,local_58);
    exatlon(local_38);
    bVar1 = std::operator==(local_38,
                            "1152 1344 1056 1968 1728 816 1648 784 1584 816 1728  1520 1840 1664 784 1632 1856 1520 1728 816 1632 185 6 1520 784 1760 1840 1824 816 1584 1856 784 1776 176 0 528 528 2000 "
                           );
    std::__cxx11::string::~string(local_38);
```

Seems like the `bvar1` holds the result of the comparison with the bytes of the password. However, at this point I feel like this is encrypted. Our goal in here is to identify which encryption type used in here. If you notice, the `exatlon` function is called before `bvar1`. The `local_38` is stored there as an argument, which also appeared in `bvar1`. 

## 2. Exatlon Function

```
string * exatlon(string *param_1)

{
  bool bVar1;
  char *pcVar2;
  string *in_RSI;
  undefined8 local_80;
  undefined8 local_78;
  allocator local_69;
  string local_68 [32];
  __cxx11 local_48 [39];
  char local_21;
  string *local_20;
  
  std::allocator<char>::allocator();
                    /* try { // try from 00404ae8 to 00404aec has its
                       CatchHandler @ 00404bc1 */
  std::__cxx11::string::string(param_1,"",&local_69);
  std::allocator<char>::~allocator((allocator<char> *)&local_69);
  local_20 = in_RSI;
  local_78 = std::__cxx11::string::begin(in_RSI);
  local_80 = std::__cxx11::string::end(local_20);
  while( true ) {
    bVar1 = __gnu_cxx::operator!=
                      ((__normal_iterator *)&local_78,
                       (__normal_iterator *)&local_80);
    if (!bVar1) break;
    pcVar2 = (char *)__gnu_cxx::__normal_iterator<>::operator*
                               ((__normal_iterator<> *)&local_78);
    local_21 = *pcVar2;
                    /* try { // try from 00404b63 to 00404b67 has its
                       CatchHandler @ 00404bfd */
    std::__cxx11::to_string(local_48,(int)local_21 << 4);
                    /* try { // try from 00404b7d to 00404b81 has its
                       CatchHandler @ 00404bec */
    std::operator+(local_68,(char *)local_48);
                    /* try { // try from 00404b93 to 00404b97 has its
                       CatchHandler @ 00404bdb */
    std::__cxx11::string::operator+=(param_1,local_68);
    std::__cxx11::string::~string(local_68);
    std::__cxx11::string::~string((string *)local_48);
    __gnu_cxx::__normal_iterator<>::operator++((__normal_iterator<> *)&local_78)
    ;
  }
  return param_1;
}
```

Above is the whole function of `exatlon`.

This part is kinda interesting, it does some kind of shifting to the left in this block of code.

```
    pcVar2 = (char *)__gnu_cxx::__normal_iterator<>::operator*
                               ((__normal_iterator<> *)&local_78);
    local_21 = *pcVar2;
                    /* try { // try from 00404b63 to 00404b67 has its
                       CatchHandler @ 00404bfd */
    std::__cxx11::to_string(local_48,(int)local_21 << 4);
                    /* try { // try from 00404b7d to 00404b81 has its
                       CatchHandler @ 00404bec */
    std::operator+(local_68,(char *)local_48);
                    /* try { // try from 00404b93 to 00404b97 has its
                       CatchHandler @ 00404bdb */
    std::__cxx11::string::operator+=(param_1,local_68);
    std::__cxx11::string::~string(local_68);
```

First, it points to our input on `pcVar2` [`local_21 = *pcVar2;`]. Then, `local_21` is typecasted into an `int` and left shifted by 4 [`(int)local_21 << 4`].

Reference on the typecasted `local_21`: `std::__cxx11::to_string(local_48,(int)local_21 << 4);`

After that, the resulting integer is converted into a `string` using `std::to_string()` and stored in `local_48`. Then, `local_48` is used to construct `local_68`. Lastly, it appends `local_68` to `param_1` and iterates using the `while` loop.

## 3. Dynamic Analysis

Now that we know what the `exatlon` function does, we get the idea that it compares the bytes stored in the `main` function. The goal of this is to identify what are the letters of the inputs and reverse the bytes seen in the `main` function.

For now, let's deepen our findings by doing dynamic analysis. Let's check how our input is **transformed**. I will set a **breakpoint** in the `local_21` because it points to the bytes in the `main`.

```
pwndbg> break *exatlon+158
Breakpoint 1 at 0x404b4b
pwndbg> r
Starting program: /home/equus/CTF/HTB_machines/rev/exatlon/exatlon_v1_unpacked

███████╗██╗  ██╗ █████╗ ████████╗██╗      ██████╗ ███╗   ██╗       ██╗   ██╗ ██╗
██╔════╝╚██╗██╔╝██╔══██╗╚══██╔══╝██║     ██╔═══██╗████╗  ██║       ██║   ██║███║
█████╗   ╚███╔╝ ███████║   ██║   ██║     ██║   ██║██╔██╗ ██║       ██║   ██║╚██║
██╔══╝   ██╔██╗ ██╔══██║   ██║   ██║     ██║   ██║██║╚██╗██║       ╚██╗ ██╔╝ ██║
███████╗██╔╝ ██╗██║  ██║   ██║   ███████╗╚██████╔╝██║ ╚████║███████╗╚████╔╝  ██║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═══╝   ╚═╝


[+] Enter Exatlon Password  : H
```

I put **H** on the input because the flag starts with `HTB{flag}`. Our input is stored in this `movzx eax, byte ptr [rax] EAX, [0x7fffffffd6f0] => 0x48`. We then need to step to the next instruction by doing `si`, and the next instruction stores our input from the GPR `RAX`, which contains `0x48`. Ryu's note: `0x48` is the ASCII value of H.

At this point, we stopped at the address `0x404be`, and we need to step through some instructions until we reach `shl eax, 4`. Why? Because this is the part where it transforms our input by shifting it to the left by 4 bits.

```
► 0x404b4e <exatlon(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)+161>    mov    byte ptr [rbp - 0x19], al      [0x7fffffffd6b7] <= 0x48
0x404b51 <exatlon(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)+164>    movsx  eax, byte ptr [rbp - 0x19]     EAX, [0x7fffffffd6b7] => 0x48
0x404b55 <exatlon(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)+168>    shl    eax, 4
0x404b58 <exatlon(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)+171>    mov    edx, eax                       EDX => 0x480
```

I did the `si` 3 times after the previous step, and now the GPR `RAX` stores `0x480`, meaning our input there is successfully shifted by 4 bits. Now you might ask what is the relation of the `0x480` to the previous values seen in the `main` function? If you convert `0x480` into an `int`, the value will become `1152`. This is a successful finding because in the `main` function, the first expected value there is `1152`. Now that we know this, we can proceed with creating the script to reverse it.

## 4. Script and Explanation

```python
order = "1152 1344 1056 1968 1728 816 1648 784 1584 816 1728 1520 1840 1664 784 1632 1856 1520 1728 816 1632 1856 1520 784 1760 1840 1824 816 1584 1856 784 1776 1760 528 528 2000".split(" ")

order_sequence = ""

for num in order:
    
    reverse = int(num) >> 4
    order_sequence += chr(reverse)
    
print(order_sequence) 
```


This is a simple script made to reverse the value and print the flag.

I will just explain the `for` part, which is important in this script.

```python
for num in order:
    
    reverse = int(num) >> 4
    order_sequence += chr(reverse)
```

I technically copied how the transformation works in `exatlon`, but instead of transforming my input, I just stored the values in the main so it can reverse them. 

```
python -u "/home/equus/CTF/HTB_machines/rev/exatlon/exploit.py"
HTB{l3g1c3l_sh1ft_l3ft_1nsr3ct1on!!}
```

## 5. Learning

1. I just learned different method to solve the binary, this include on how to reverse the shifting method.
2. I realized that even though the shifting happens in **Ghidra**, sometimes I need to do dynamic analysis and  use **pwndbg** to further analyze my findings, in this case I saw how my input is getting transformed real time.
