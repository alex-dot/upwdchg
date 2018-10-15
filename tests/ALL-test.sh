#!/bin/bash
# -*- mode:shell-script; tab-width:2; sh-basic-offset:2; intent-tabs-mode:nil; -*-
# ex: filetype=sh tabstop=2 softtabstop=2 shiftwidth=2 expandtab autoindent smartindent
set -e


## Environment
[ "$(dirname "$0")" != '.' ] && echo "ERROR: Please run tests from their actual directory" && exit
source ./resources/ENVIRONMENT
mkdir -p ./tmp/plugins.d
trap 'rm -f ./tmp/*.token ./tmp/*.nonce ./tmp/plugins.d/*' EXIT
trap 'echo; echo "********************************************************************************"; echo "* NOPE!!! NO GO!!!"' ERR


## Python unit tests
#  deb: python3, python3-configobj, python3-pycryptodome

# (existing) Token reader
echo
echo "********************************************************************************"
echo "* TEST(Python): (Existing) Token reader ... "
rm -f ./tmp/*.token
cp -p ./resources/*.token ./tmp/.
./python-tokenreader-test.py

# (existing) Token data
echo
echo "********************************************************************************"
echo "* TEST(Python): (Existing) Token data ... "
rm -f ./tmp/*.token
cp -p ./resources/password-nonce.token ./tmp/.
./python-tokendata-test.py

# Token writer (and reader/data)
echo
echo "********************************************************************************"
echo "* TEST(Python): Token writer (and reader/data) ... "
rm -f ./tmp/*.token
./python-tokenwriter-test.py


## Python->PHP unit tests
#  deb: phpunit, php-mcrypt, php-mbstring

# (existing) Token reader
echo
echo "********************************************************************************"
echo "* TEST(Python->PHP): (Existing) Token reader ... "
rm -f ./tmp/*.token
cp -p ./resources/password-nonce.token ./tmp/.
phpunit --tap ./php-tokenreader-test.php && echo 'OK'
[ $? -ne 0 ] && echo 'FAIL' && exit

# (existing) Token data
echo
echo "********************************************************************************"
echo "* TEST(Python->PHP): (Existing) Token data ... "
rm -f ./tmp/*.nonce
cp -p ./resources/password-nonce.token ./tmp/test.nonce
phpunit --tap ./php-tokendata-test.php && echo 'OK'
[ $? -ne 0 ] && echo 'FAIL' && exit


## PHP->Python unit tests
#  deb: phpunit, php-mcrypt, php-mbstring

# Token writer (and reader)
echo
echo "********************************************************************************"
echo "* TEST(PHP->...): Token writer ... "
rm -f ./tmp/*.nonce
cp -p ./resources/password-nonce.token ./tmp/.
phpunit --tap ./php-tokenwriter-test.php && echo 'OK'
[ $? -ne 0 ] && echo 'FAIL' && exit
echo
echo "* TEST(...->Python): Token reader ... "
./python-tokenreader-test.py
echo
echo "* TEST(...->Python): Token data ... "
./python-tokendata-test.py


## Command-line test

# Utilities
echo
echo "********************************************************************************"
./cli-utils-test.sh

# Plugins (individually)
echo
echo "********************************************************************************"
./cli-plugins-test.sh

# Plugins (process)
echo
echo "********************************************************************************"
./cli-process-test.sh

# Daemon
echo
echo "********************************************************************************"
./cli-daemon-test.sh


## DONE
echo
echo "********************************************************************************"
echo "* CONGRATULATIONS! ALL PASS!"
