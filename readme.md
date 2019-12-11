### recode代码审计工具

>方便在Mac/Linux下使用   

> 匹配规则部分来自于seay代码审计工具

> 开发版本为python 3.8
> 此版本为demo
### 使用方法:
`python recode.py {folder}`

```
$ python recode.py xssplatform
xssplatform/libs/plugins/function.html_image.php : 64 : 双$$符号可能存在变量覆盖漏洞
xssplatform/libs/sysplugins/smarty_internal_compile_private_modifier.php : 55 : call_user_func函数参数包含变量，可能存在代码执行漏洞
xssplatform/./c.php : 20 : 文件操作函数中存在变量，可能存在任意文件读取/删除/修改/写入等漏洞
xssplatform/./c.php : 22 : 读取文件函数中存在变量，可能存在任意文件读取漏洞
xssplatform/libs/sysplugins/smarty_internal_resource_file.php : 72 : 读取文件函数中存在变量，可能存在任意文件读取漏洞
```

- [x] 审计规则自定义
- [ ] 生产项目配置文件
- [ ] 将漏洞进行分类 方便观看
- [ ] 调用ide进行编辑
- [ ] 生成报告