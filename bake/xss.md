前期准备：linux下搭建dvwa需要lamp环境，其php版本不能太高，php7.0无法使用，php5.6可以;
#### XSS定义
CSS(Cross Site Script)又叫XSS,中文意思：[跨站脚本攻击](http://baike.baidu.com/view/2633667.htm)。它指的是恶意攻击者往Web页面里插入恶意html代码，当用户浏览该页之时，嵌入其中Web里面的html代码会被执行。XSS的攻击目标是为了盗取客户端的cookie或者其他网站用于识别客户端身份的敏感信息。获取到合法用户的信息后，攻击者甚至可以假冒最终用户与网站进行交互。
#### XSS的原理
也就是往HTML中注入脚本，HTML指定了脚本标记<script></script>.在没有过滤字符的情况下，只需要保持完整无错的脚本标记即可触发XSS，假如我们在某个资料表单提交内容,表单提交内容就是某个标记属性所赋的值，我们可以构造如下值来闭和标记来构造完整无错的脚本标记，`"><script>alert('Xss');</script><"`
#### 反射型XSS
##### 等级Low
源代码
```php
<?php
header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Feedback for end user
    echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
}

?> 
```
这里随便输入Word试一下：
`word<script>alert('Xss');</script> ;`![基本的xss](https://upload-images.jianshu.io/upload_images/9464729-448fa2c12d5bea08.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
观察到调用函数输出了Xss弹窗,后面为Word,其实<script>”注入语句“</script>可以完成许多功能。
##### 等级Medium
源代码：
```php
<?php
header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Get input
    $name = str_replace( '<script>', '', $_GET[ 'name' ] );

    // Feedback for end user
    echo "<pre>Hello ${name}</pre>";
}

?> 
```
观察发现使用`str_replace`进行了黑名单过滤，绕过这个不成问题，使用 
###### 双写绕过
`<scri<script>pt>alert(/test/);</script>`
###### 大小写混写绕过
`<sCripT>alert(/test/);</script>`
![xss](https://upload-images.jianshu.io/upload_images/9464729-f3d2f4ad6391c2a5.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
##### 等级High
```php
<?php
header ("X-XSS-Protection: 0");
// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Get input
    $name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] );
    // Feedback for end user
    echo "<pre>Hello ${name}</pre>";
}

?> 
```
使用正则进行匹配，过滤了大小写混合写入已经双写，但是可以使用img、body等标签的事件以及iframe标签的src注入恶意的js代码进行漏洞利用
`<img src=1 onerror=alert('test')>`
![xss](https://upload-images.jianshu.io/upload_images/9464729-6c8fc0dd38766d98.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
##### 等级Impossible
源代码:
```php
<?php
// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );
    // Get input
    $name = htmlspecialchars( $_GET[ 'name' ] );
    // Feedback for end user
    echo "<pre>Hello ${name}</pre>";
}
// Generate Anti-CSRF token
generateSessionToken();
?> 

```
htmlspecialchars() 函数把一些预定义的字符转换为 HTML 实体。以防止浏览器将其作为HTML元素。这样会将用户输入的内容都不作为标签以提高安全性。
预定义的字符是：

    & （和号）成为 &amp;
    " （双引号）成为 &quot;
    ' （单引号）成为 '
    < （小于）成为 &lt;
    > （大于）成为 &gt;
一些常用的xss语句
```
   <script>alert(/test/)</script> 最普通的xss代码
   <script>alert(document.cookie);</script> 获取cookie
   <img src="javascript:alert(/test/)"> img链接地址xss
   <script src="test.js"> <script> 外部调用攻击代码ls.js
   <script alert('test)</SCRIPT> 注释方法防止过滤
   <img src="" onerror=alert("xss")> 加载图像失败执行
   <iframe onload=alert('test')> 框架
   <script>location='test.com';</script> 跳转某页面
```
#### 存储型XSS
##### 等级Low
源代码:
```php
<?php
if( isset( $_POST[ 'btnSign' ] ) ) {
    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );

    // Sanitize message input
    $message = stripslashes( $message );
    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

    // Sanitize name input
    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

    // Update database
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    //mysql_close();
}

?> 
```
###### 部分函数讲解
trim() 函数移除字符串两侧的空白字符或其他预定义字符。
相关函数：

    ltrim() - 移除字符串左侧的空白字符或其他预定义字符
    rtrim() - 移除字符串右侧的空白字符或其他预定义字符

stripslashes()：删除由 addslashes() 函数添加的反斜杠。该函数用于清理从数据库或 HTML 表单中取回的数据。(若是连续二个反斜杠，则去掉一个，保留一个；若只有一个反斜杠，就直接去掉。)；
mysqli_real_escape_string：转义字符串中的特殊字符；

name栏输入发现有字数限制，那就抓包改数据；
![抓包](https://upload-images.jianshu.io/upload_images/9464729-7c8e576b98babe91.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
message栏正常输入即可，`<script>alert('test');</script>`
![](https://upload-images.jianshu.io/upload_images/9464729-211dc5368255042b.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
##### 等级Medium
源代码：
```php
<?php
if( isset( $_POST[ 'btnSign' ] ) ) {
    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );

    // Sanitize message input
    $message = strip_tags( addslashes( $message ) );
    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    $message = htmlspecialchars( $message );

    // Sanitize name input
    $name = str_replace( '<script>', '', $name );
    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

    // Update database
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    //mysql_close();
}

?> 
```
部分函数讲解
```strip_tags()``` 函数剥去字符串中的 HTML、XML 以及 PHP 的标签，但允许使用`<b>`标签。
```addslashes()``` 函数返回在预定义字符（单引号、双引号、反斜杠、NULL）之前添加反斜杠的字符串。
其对message参数使用了`htmlspecialchars`函数进行编码，因此无法对message参数注入XSS代码，但是对于name参数，简单过滤了`<script>`字符串，仍然存在存储型的XSS。
使用双写`<scri<script>pt>alert('test')`
![改包](https://upload-images.jianshu.io/upload_images/9464729-3a7307e13813a512.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
成功弹框
![medium](https://upload-images.jianshu.io/upload_images/9464729-619ffba35aee9ede.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
大小写混合绕过`<sCrIpt>alert('test')`
##### 等级High
源代码：
```php
<?php
if( isset( $_POST[ 'btnSign' ] ) ) {
    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );

    // Sanitize message input
    $message = strip_tags( addslashes( $message ) );
    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    $message = htmlspecialchars( $message );

    // Sanitize name input
    $name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $name );
    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

    // Update database
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    //mysql_close();
}
?> 
```
这里使用正则表达式过滤了`<script>`标签，但是依然存在`img、iframe`等其它危险的标签，因此name参数仍然有存储型XSS
抓包改name数据`=<img src=1 onerror=alert('test')>`
![bao.png](https://upload-images.jianshu.io/upload_images/9464729-1e4aa05bb6b8bf55.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
成功弹框
![图片.png](https://upload-images.jianshu.io/upload_images/9464729-0b8b33fa05ceba20.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
##### 等级Impossible
源代码：
```php
<?php
if( isset( $_POST[ 'btnSign' ] ) ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );

    // Sanitize message input
    $message = stripslashes( $message );
    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    $message = htmlspecialchars( $message );

    // Sanitize name input
    $name = stripslashes( $name );
    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    $name = htmlspecialchars( $name );

    // Update database
    $data = $db->prepare( 'INSERT INTO guestbook ( comment, name ) VALUES ( :message, :name );' );
    $data->bindParam( ':message', $message, PDO::PARAM_STR );
    $data->bindParam( ':name', $name, PDO::PARAM_STR );
    $data->execute();
}
// Generate Anti-CSRF token
generateSessionToken();

?> 
```

这个就比较高级了，对name和message均进行了`htmlspecialchars`过滤
###### 存储型和反射型的区别
- 存储型 
存储型XSS，持久型，代码是存储在服务器中的，如果没有过滤或过滤不严，那么这些代码将储存到服务器中，用户访问该页面的时候触发代码执行。这种XSS比较危险，容易造成蠕虫，盗窃cookie等。
- 反射型
反射型XSS，非持久化，需要欺骗用户手动去点击链接才能触发XSS代码，一般容易出现在搜索页面。
