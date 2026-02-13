#!/bin/bash

CWD=`pwd`
SCRIPT_DIR=`cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd`
cd $SCRIPT_DIR

go run main.go

mkdir -p ../../files/acceptedroots
cd ../../files/acceptedroots
git restore --staged *.pem *.txt
git rm *.pem *.txt
rm *.pem *.txt
mv $SCRIPT_DIR/*.pem .
mv $SCRIPT_DIR/*.txt .
git add *.pem *.txt

cd $CWD
