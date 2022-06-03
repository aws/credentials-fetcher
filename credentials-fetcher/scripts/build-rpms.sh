# Initial script to create source and binary rpms

# set up rpm directory structure in ~/rpmbuild
rpmdev-setuptree

# Manual steps to make a .tar.gz in ~/rpmbuild/SOURCES directory
# TBD: Automate with a better method
# tar cvfz ~/rpmbuild/SOURCES/credentials-fetcher-0.0.1.tar.gz ../
# Make a temp directory and copy above tar.gz file
# Extract tar.gz and rename the directory to credentials-fetcher-0.0.1
# Create a new tar.gz of the renamed directory and copy to ~/rpmbuild/SOURCES

cp credentials-fetcher.spec ~/rpmbuild/SPECS

cd ~/rpmbuild/SPECS

# Source rpm
rpmbuild -bs credentials-fetcher.spec

# Binary rpm
rpmbuild -ba credentials-fetcher.spec

# Query the binary rpm
# TBD: The binary is a place-holder at this time.
# $ rpm -qlp /home/samiull/rpmbuild/RPMS/x86_64/credentials-fetcher-0.0.1-1.amzn2int.x86_64.rpm
# /usr/bin/credentials-fetcherd
