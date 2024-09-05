#!/bin/bash
#
mkdir -p build && cd build
if [ $? -ne 0 ]; then
   echo "ERROR: Failed at creating build dir"
   exit 1
fi
cmake3 .. -DCODE_COVERAGE=ON && make
if [ $? -ne 0 ]; then
   echo "ERROR: Failed at build"
   exit 1
fi

echo "Start running the credentials-fetcher daemon"
echo "After running gRPC clients, you must exit the credentials-fetcher daemon using 'touch /tmp/credentials_fetcher_exit.txt'"
echo "Note: If you use ctrl-c or sigkill, the gcda files will not get created"

echo "Run the following in the build directory:"

echo "\tpip install gcovr"
echo "\tgcovr --html-details coverage.html  -r .."
echo "\ttar cvfz coverage.tar.gz *.html"
echo "To view code coverage, extract coverage.tar.gz and start browsing at coverage.html"
exit 0
