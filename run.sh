#!/bin/sh

ant
gp -delete 0102030405
gp -install build/Mycard221.cap
python3 Client/clientHelloFirst.py
