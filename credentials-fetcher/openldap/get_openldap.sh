#!/bin/sh

set -x

echo "=======Building openldap for the ldapsearch utility======="

echo $PWD
echo "Arg is $1"

DIR="./"
if [ -d $1 ]; then
  DIR=$1
fi

if [ ! -d openldap ]; then
   cd $DIR && git clone https://github.com/openldap/openldap.git && cd openldap && ./configure --with-cyrus-sasl
fi

echo "==========openldap build done==========="
