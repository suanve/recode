#!/usr/bin/env python3
#coding=utf-8
from config import *
from libs.rules import rule
import sys
import os
import re

def getFilefree(rootDir):
    fileSet = set()
    for dir_, _, files in os.walk(rootDir):
        for fileName in files:
            relDir = os.path.relpath(dir_, rootDir)
            relFile = os.path.join(relDir, fileName)
            fileSet.add(relFile)
    return fileSet

path = sys.argv[1]
s = getFilefree(path)

def checkCode(filePath):
    filePath = path + "/" + filePath
    if filePath.split(".")[-1] not in checkExt:
        return
    lineNum = 0
    with open(filePath, 'r', encoding="utf8", errors='ignore') as file:
            for line in file.readlines():
                    lineNum = lineNum + 1
                    for pattern in rule.keys():
                        if len(re.findall(rule[pattern]['regText'],line)) != 0:
                            log = f"{filePath} : {lineNum} : {rule[pattern]['content']}"
                            print(log)
                    
for i in s:
    checkCode(i)