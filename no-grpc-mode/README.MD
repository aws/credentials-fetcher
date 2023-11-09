#compile no_grpc_mode on AmazonLinux2

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
  cd ..
  
  #Install packages need by Credentials-Fetcher
  sudo yum install glib* -y
  sudo yum install jsoncpp-devel jsoncpp -y
  sudo yum install systemd-devel -y
 
  #Download Credentials-Fetcher code
  git clone https://github.com/awsjohns/credentials-fetcher
  cd credentials-fetcher/
  git switch no_grpc_mode
  cd no-grpc-mode/
  mkdir build
  cd build
   
  cmake ../
  make -j 4

  sudo cp credentials_fetcher_utf16_private.exe /usr/sbin/
  sudo cp credentials_fetcher_utf16_private.runtimeconfig.json /usr/sbin/
  
  #run it
  #set CF_CRED_SPEC_FILE=/var/credentials-fetcher/credspec/credspec.json
  export CF_CRED_SPEC_FILE=/home/ec2-user/credentials-fetcher/no-grpc-mode/build/credspec.json
  sudo yum install realmd -y
  sudo yum install krb5-workstation -y
  sudo yum install openldap -y
  sudo yum install openldap-clients -y
  sudo yum install cyrus-sasl-gssapi -y
  
  
  #make sure EC2 Instance Profile has permissions to AWS Secrets Manager
  export AWS_REGION=us-east-1
 ./credentials-fetcherd --aws_sm_secret_name gmsa-plugin-input
