```
---
title: CTFhub文件上传 //文章标题
date: 2020-03-18 17:35:21
tags:
    - php //文章标签
categories:
    - web //文章目录
keywords: 
    - 文件上传 //文章关键词
description: 
    - CTF //文章描述
toc: true
thumbnail:  //文章略缩图<正方形 可以缺省>
banner:  //文章头图<可以缺省>
---
```

作者:Retr_0

# CTFhub 文件上传

一般所看到的文件上传，除了连🐎那就是通过htaccess来更改php.ini的配置。
而也存在是利用上传点进行php反序列化漏洞或是其他的注入。
本文主要进行CTFhub上文件上传题的复现。
当然可以传一些RCE但是就反而复杂了，直接传🐎
就可以更简单一些

## 第一题无任何过滤。
上传一个php文件包含一句话木🐎
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/5I2EFA@9@TY0B4PVLTUZO.png)

--------
## 第二题前端认证
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/63X7YVT9X@2DLR0-1024x549.png)
抓包改包传就可以了。
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/933RBI5SDB1TK_5RXO481HW-954x1024.png)
蚁剑连上
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/HGF9DFAYEI8EBHOLOJ.png)

-----
## .htaccess文件上传
这个是比较特别的一种解析错误
>htaccess文件是Apache服务器中的一个配置文件，它负责相关目录下的网页配置。通过htaccess文件，可以帮我们实现：网页301重定向、自定义404错误页面、改变文件扩展名、允许/阻止特定的用户或者目录的访问、禁止目录列表、配置默认文档等功能

那么还是先看题目吧
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/AGW7RDXTS89RUHLIKM8J-1024x549.png)
基本过滤了所有的文件类型，唯独.htaccess没有。
那么上传这个文件能够得到什么
仔细看过之后，
发现jpg还是可以用的。那么考虑还是传jpg并且用htaccess让服务器解析jpg转换为解析jpg的格式
```
payload:AddType   application/x-httpd-php    .jpg
```
剩下的就传一个带🐎的jpg即可
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/@RDFYCS1RCF7KKWIE4Y.png)
得到了flag.

------
## MIME验证
>MIME:客户端软件，区分不同种类的数据，例如web浏览器就是通过MIME类型来判断文件是GIF图片，还是可打印的PostScript文件。web服务器使用MIME来说明发送数据的种类， web客户端使用MIME来说明希望接收到的数据种类。
>也就是服务端MIME类型检测是通过检查http包的Content-Type字段中的值来判断上传文件是否合法的。那就好办了，不管我上传什么类型的文件，我只要修改Content-Type字段来让检测通过就行了。
>作者：Maxx_FAN
>链接：https://www.jianshu.com/p/01c1d5f05852
>来源：简书
>著作权归作者所有。商业转载请联系作者获得授权，非商业转载请注明出处。

那和第二个就没啥区别了。。。
只需要抓包改包。
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/89EAUO_QKYLQE2R7H.png)
不多介绍了
## 文件头检查
所谓的文件头我在misc的介绍中讲过了，也就是16进制下每个文件固有的东西。那么我们可以通过编辑整个图片，把一句换木马夹在里面。这样检验文件头也就自然没用了。
抓包改后缀以及图片末尾
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/AM5MNCJN9H898Q238ZYG7-954x1024.png)

![](http://www.zhaobairen.club/wp-content/uploads/2020/03/M8WA2ZX285F3CCMCVJYYIV-954x1024.png)
那么就可以上传getshell了。
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/1YZVATPLC9R_WEZY7Q.png)
## %00截断绕过
这个是一个耳熟能详的方法了。
我想先给大家介绍下原理：
>0x00是字符串的结束标识符，攻击者可以利用手动添加字符串标识符的方式来将后面的内容进行截断，而后面的内容又可以帮助我们绕过检测。

也同样有限制条件
>PHP<5.3.29，且GPC关闭
>GPC功能之一就是检查%00被错误认知的情况。所以需要关闭。

```
admin.php%00;a.jpg
```
>原来我也是单纯的认为在文件名处进行截断，如xx.php%00.jpg，这样其实是不对的，提取的时候碰到%00就会认为字符串提取结束了，后面的.jpg就不会再提取，那样的效果还是等于上传了.php的文件，无法绕过。正确的做法还是数据包中必须有上传文件的path才行。结合上传路径+文件名，进行截断。

但是这道题如果直接传的话会变成rand。无法找到文件，所以需要再次截断。
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/RC3ERJZRBDE_RJS53DJJ-954x1024.png)
然后getshell就可以了
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/GVYR6CKURZD_K2TGK_VKK.png)

--------
## 双写绕过
题如其名
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/9X0@6@JN1EYWG4PW_VA-1024x549.png)
改成.pphphp就行
传马连上就成了。
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/RV3UY_JIFFI8R7@FZNLGEH-1024x549.png)
![](http://www.zhaobairen.club/wp-content/uploads/2020/03/XZI_EVTER0A79IWK5J.png)
就结束了

------