import json
rule = {}


rule['pickle_unserialize'] = {
    'regText':r"""pickle.(dumps|loads)\s{0,5}\(""",
    'content':"存在pickle反序列化操作,可能存在反序列化漏洞"
}
rule['yaml_unserialize'] = {
    'regText':r"""yaml.(dumps|loads)\s{0,5}\(""",
    'content':"存在yaml反序列化操作,可能存在反序列化漏洞"
}

rule['exec1'] = {
    'regText':r"""subprocess\.(run|call|check_output|getoutput|getstatusoutput)\s{0,5}\(""",
    'content':"存在subprocess命令执行函数,可能存在命令执行漏洞"
}

rule['exec2'] = {
    'regText':r"""os\.(system)\s{0,5}\(""",
    'content':"存在system命令执行函数,可能存在命令执行漏洞"
}
rule['exec3'] = {
    'regText':r"""\b(popen)\s{0,5}\(""",
    'content':"存在popen命令执行函数,可能存在命令执行漏洞"
}

rule['sql_select'] = {
    'regText':r"""select\s{1,4}.{1,60}from.{1,50}where\s{1,3}.{1,50}=["\s\.]{0,10}\$\w{1,20}((\[["']|\[)\${0,1}[\w\[\]"']{0,30}){0,1}""",
    'content':"SQL语句select中条件变量无单引号保护，可能存在SQL注入漏洞"
}


rule['sql_delete'] = {
    'regText':r"""delete\s{1,4}from.{1,20}where\s{1,3}.{1,30}=["\s\.]{0,10}\$\w{1,20}((\[["']|\[)\${0,1}[\w\[\]"']{0,30}){0,1}""",
    'content':"SQL语句delete中条件变量无单引号保护，可能存在SQL注入漏洞"
}

rule['sql_insert'] = {
    'regText':r"""insert\s{1,5}into\s{1,5}.{1,60}\$\w{1,20}((\[["']|\[)\${0,1}[\w\[\]"']{0,30}){0,1}""",
    'content':"SQL语句insert中插入变量无单引号保护，可能存在SQL注入漏洞"
}

rule['sql_update'] = {
    'regText':r"""update\s{1,4}.{1,30}\s{1,3}set\s{1,5}.{1,60}\$\w{1,20}((\[["']|\[)\${0,1}[\w\[\]"']{0,30}){0,1}""",
    'content':"SQL语句delete中条件变量无单引号保护，可能存在SQL注入漏洞"
}

print(json.dumps(rule))