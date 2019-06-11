#! /usr/bin/python
import os
import sys
import subprocess

def Excute(cmd):
    popen = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             universal_newlines=True)
    stdout = popen.communicate()[0]
    return stdout

def GenerateCommand(loc, addr):
    cmd = ['addr2line', '-e', '../build/output/bin/tinyara', addr]
    res = Excute(cmd)
    isvalid = res.find("??")
    if isvalid == -1:
        stack_addr = "0x%x"%(loc)
        res = res[:len(res) - 1] # remove additional carriage return
        print(stack_addr + ": " + addr + ": " + res);


def parsing_data(path):
    with open(path) as f:
        while True:
            line = f.readline()
            if not line:
                break
            addr = ""
            while True:
                pos = line.find(":")
                if pos == -1:
                    break;
                addr = line[pos - 8 : pos]
                line = line[pos + 1:]

            data = line.split()
            size = len(data)

            for i in range(0, size):
                GenerateCommand(int(addr, 16) + (size-i-1) * 4, data[size-i-1])


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("usage: %s [path]" % sys.argv[0])
        exit(1)

    path = sys.argv[1]
    parsing_data(path)

