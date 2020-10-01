#!/bin/sh

if ! git remote | grep upstream > /dev/null
then 
    git remote add upstream https://github.com/rizinorg/rizin.git
fi
test -d rizin && git fetch upstream && git rebase --onto master upstream/master
