### recode代码审计工具

> 方便在Mac/Linux下使用的一个代码审计工具

> 匹配规则部分来自于seay代码审计工具
> 准备做支持多语言的审计
> 开发版本为python 3.9
> 此版本为demo
### 使用方法:
`python3 recode.py -h`

```
$ recode.py  ./
evil/1.php:2 : eval或者assertc函数中存在变量，可能存在代码执行漏洞
./nu.php:5 : eval或者assertc函数中存在变量，可能存在代码执行漏洞
./un.php:6 : eval或者assertc函数中存在变量，可能存在代码执行漏洞
./un.php:17 : unserialize函数中存在变量,可能存在反序列化漏洞
./2.php:79 : 命令执行函数中存在变量，可能存在任意命令执行漏洞
./2.php:79 : 远程请求函数中存在变量,可能存在SSRF漏洞
evil/3.php:2 : 读取文件函数中存在变量，可能存在任意文件读取漏洞
evil/3.php:2 : 文件操作函数中存在变量，可能存在任意文件读取/删除/修改/写入等漏洞
```


```
$ recode.py -t python ./
./1.py:3 : 存在pickle反序列化操作,可能存在反序列化漏洞
./1.py:4 : 存在popen命令执行函数,可能存在命令执行漏洞
apps/deploy/views.py:246 : 存在subprocess命令执行函数,可能存在命令执行漏洞
apps/monitor/executors.py:40 : 存在subprocess命令执行函数,可能存在命令执行漏洞
```