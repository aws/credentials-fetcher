sudo yum install git -y
sudo yum install gcc10-c++ -y
sudo mv /usr/bin/gcc /usr/bin/gcc-7.3
sudo ln -s /usr/bin/gcc10-cc /usr/bin/gcc
sudo mv /usr/bin/g++ /usr/bin/g++-7.3
ln -s /usr/bin/gcc10-c++ /usr/bin/g++
sudo ln -s /usr/bin/gcc10-c++ /usr/bin/g++
sudo mv /usr/bin/c++ /usr/bin/c++-7.3
ln -s /usr/bin/gcc10-c++ /usr/bin/c++
sudo ln -s /usr/bin/gcc10-c++ /usr/bin/c++

sudo yum install openssl-devel -y
sudo yum install openssl-devel -y
  
#need a newer version of CMake so compile from source
git clone https://github.com/Kitware/CMake.git -b release \
   && cd CMake && ./configure && make -j8 &&  pwd && sudo make install
  
#install DotNet 6  
sudo rpm -Uvh https://packages.microsoft.com/config/centos/7/packages-microsoft-prod.rpm  
sudo yum install aspnetcore-runtime-6.0 -y
sudo yum install dotnet-sdk-6.0 -y
  
#Install packages needed by Credentials-Fetcher to compile
sudo yum install glib* -y
sudo yum install jsoncpp-devel jsoncpp -y
sudo yum install systemd-devel -y
 
#compile
mkdir build
cd build

cmake ../
make -j 4

sudo cp credentials_fetcher_utf16_private.exe /usr/sbin/
sudo cp credentials_fetcher_utf16_private.runtimeconfig.json /usr/sbin/
