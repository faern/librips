#!/bin/sh

egrep "^//\!" src/lib.rs | sed 's/\/\/\! //g' | sed 's/\/\/\!//g' > README.md
