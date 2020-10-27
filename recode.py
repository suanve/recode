#!/usr/bin/env python3
import argparse
import os
from core.audit import Audit
class Run:

    def __init__(self):
        self.cmdline()

    # 命令行参数
    def cmdline(self):
        parser = argparse.ArgumentParser(description='You can perform an automatic code audit by entering the type and directory of the source code you want to audit.')
        parser.add_argument('-t','--type',metavar="type",type=str,default='php',
                            help='Enter the Code Type for the audit,Support php,py,go,shell')
        parser.add_argument('path', metavar='path', type=str,
                            help='Enter the Code Path for the audit')
        args = parser.parse_args()
        self.type = args.type
        self.path = args.path

if __name__ == "__main__":
    run = Run()
    scan = Audit(run.path,run.type)
    scan.Scan()
    