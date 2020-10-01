#!/bin/sh

git clone https://github.com/rizinorg/rizin-extras
cd rizin-extras
./configure --prefix=/usr
make
sudo make symstall
