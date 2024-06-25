import os
import sys
from parser.parser import *


def run(to_search):
    for file in os.listdir(to_search):
        if os.path.isdir(os.path.join(to_search, file)):
            run(os.path.join(to_search, file))
        else:
            file = os.path.join(to_search, file)
            if file.endswith(".log"):
                if os.path.basename(file).split('.')[0] == "kubs":
                    KubsParser(file)
                if os.path.basename(file).split('.')[0] == "docker-bench-security":
                    DockerParser(file)
            if file.endswith(".json"):
                GrypeParser(file)
            if file.endswith(".out"):
                LinPeasParser(file)


def check():
    if len(sys.argv) == 1:
        print("you must enter a PATH to search for logs and a PATH to save the result")
    if len(sys.argv) == 2:
        if os.path.isfile(sys.argv[1]) or os.path.isdir(sys.argv[1]):
            print("you must enter a PATH to save the result")
        else:
            print("you must enter a PATH to search for logs and a PATH to save the result")
    if len(sys.argv) == 3:
        if (os.path.isfile(sys.argv[1]) or os.path.isdir(sys.argv[1])) and (
                os.path.isfile(sys.argv[1]) or os.path.isdir(sys.argv[1])):
            run(sys.argv[1])
            BaseParser.compile(sys.argv[2])
        elif os.path.isfile(sys.argv[1]) or os.path.isdir(sys.argv[1]):
            print("you must enter a PATH to save the result")
        elif os.path.isfile(sys.argv[2]) or os.path.isdir(sys.argv[2]):
            print("you must enter a PATH to search for logs")
        else:
            print("you must enter a PATH to search for logs and a PATH to save the result")


if __name__ == '__main__':
    check()
