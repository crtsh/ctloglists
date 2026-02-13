#!/bin/bash

CWD=`pwd`
SCRIPT_DIR=`cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd`
cd $SCRIPT_DIR

go run main.go

mkdir -p ../../files/acceptedroots
cd ../../files/acceptedroots
git restore --staged *.pem
git rm *.pem
rm *.pem
mv $SCRIPT_DIR/*.pem .
git add *.pem

cd $CWD
