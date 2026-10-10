Today, I learned how to modify a program's data directly in memory while debugging it with GDB and Pwndbg. This task required me to patch a binary or specifically a **memory data patching**. I was given a program called hello_world.

```
file hello_world
hello_world: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=d960fac581b3aa8fc052d6695dc284d34afb16bf, not stripped
```

It's a 32-bit binary with an i386 architecture. Upon running this binary it only prints Hello World.

```
./hello_world
hello world!
```

Now, we are skipping from the instructions of the Nightmare guide on their website and go straight on where is the `hello world!` is called. 

```
pwndbg> disass main
Dump of assembler code for function main:
0x080483fb <+0>:     lea    ecx,[esp+0x4]
0x080483ff <+4>:     and    esp,0xfffffff0
0x08048402 <+7>:     push   DWORD PTR [ecx-0x4]
0x08048405 <+10>:    push   ebp
0x08048406 <+11>:    mov    ebp,esp
0x08048408 <+13>:    push   ecx
0x08048409 <+14>:    sub    esp,0x4
0x0804840c <+17>:    sub    esp,0xc
0x0804840f <+20>:    push   0x80484b0
0x08048414 <+25>:    call   0x80482d0 <puts@plt>
  s: 0x80484b0 ◂— 'hello world!'
0x08048419 <+30>:    add    esp,0x10
0x0804841c <+33>:    mov    eax,0x0
0x08048421 <+38>:    mov    ecx,DWORD PTR [ebp-0x4]
0x08048424 <+41>:    leave
0x08048425 <+42>:    lea    esp,[ecx-0x4]
0x08048428 <+45>:    ret
```

As you can see below, at the address of `0x08048414` the binary is calling the `<puts@plt>`, for those who didn't know the `<puts@plt>` is a function in assembly that is similar to C which is `puts()` so `puts()` is just printing a string into the terminal and adding a new line. Now I break at the `*main+25` or more specifically at the address of `0x08048414` that calls the function. The tasks then taught me on how to change the value during runtime. 

`pwndbg> set {char [12]} 0x080484b0 = "hello venus"`

The above command does a few things, `set` modifies the value in the target's process's memory, `{char [12]}` we setup a char with an array of 12 characters, now you might ask me why is it 12 characters even though the **hello venus** are just 11 characters, the answer for that is we need a null terminator at the end \0. Going back, we will print the value of the address of `0x80484b0` as a string.

```
pwndbg> x/s 0x80484b0
0x80484b0:      "hello venus"
```

Pretty cool ain't it? It's my first time actually writing these kind of writeups lmao.
