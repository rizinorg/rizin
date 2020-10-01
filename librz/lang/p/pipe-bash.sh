#!/bin/bash

( cat <&${RZ_PIPE_IN} ) &
r2cmd() { echo "$1" >&${RZ_PIPE_OUT} ; }

r2cmd "x 64"
r2cmd "pd 10"
