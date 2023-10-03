#!/bin/sh

set -x

if [ ! -f credentials-fetcherd ];
then
   echo "**ERROR: Please copy the credentials-fetcher binary to this directory"
   exit 1
fi

LIB_FILES=$(ldd ./credentials-fetcherd | grep -v linux-vdso | grep -v ld-linux | awk '{print $3}')

rm -rf libs
mkdir -p libs

for f in $LIB_FILES;
do
    cp $f libs
done

\rm -rf build-dir
flatpak-builder build-dir org.flatpak.Credentials-fetcher.yml
flatpak-builder --user --install --force-clean build-dir org.flatpak.Credentials-fetcher.yml
#flatpak run  --filesystem=home org.flatpak.Credentials-fetcher

exit 0
