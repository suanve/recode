import os
import re
from libs.config import checkExt
import json

class Audit(object):

    # 获取需要审计的目录
    def __init__(self,rootDir,ctype) -> None:
        self.rootDir = rootDir
        self.ctype = ctype
        self.checkExt = checkExt.get(ctype)
        self.getFilefree(rootDir)
        self.LoadRule()
    
    # 获取指定目录的所有文件
    def getFilefree(self,rootDir):
        fileSet = set()
        for dir_, _, files in os.walk(rootDir):
            for fileName in files:
                relDir = os.path.relpath(dir_, rootDir)
                relFile = os.path.join(relDir, fileName)
                filePath = self.rootDir + "/" + relFile
                if filePath.split(".")[-1] not in self.checkExt:
                    continue
                fileSet.add(relFile)
        self.fileSet = fileSet


    # 设置对应的规则
    def LoadRule(self):
        path = os.path.split(os.path.realpath(__file__))[0] + "/../rules/"+ self.ctype 
        if os.path.exists(path):
            self.rule = json.loads(open(path,'r').read())
        else:
            print(f"[-] {self.ctype} not found!")
    # 调用对应的规则进行审计
    def checkCode(self,filePath):
        lineNum = 0
        with open(filePath, 'r', encoding="utf8", errors='ignore') as file:
                for line in file.readlines():
                        lineNum = lineNum + 1
                        for pattern in self.rule.keys():
                            if len(re.findall(self.rule[pattern]['regText'],line)) != 0:
                                log = f"{filePath}:{lineNum} : {self.rule[pattern]['content']}"
                                print(log)
    def Scan(self):
        for filepath in self.fileSet:
            filepath = self.rootDir+ "/" + filepath 
            self.checkCode(filepath)