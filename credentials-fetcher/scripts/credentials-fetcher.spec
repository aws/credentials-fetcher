Name:           credentials-fetcher
Version:        0.0.1
Release:        1%{?dist}
Summary:        credentials-fetcher is a daemon that refreshes tickets or tokens periodically.

License:        Apache 2.0
URL:            tbd-project.com
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cmake3 make

%description
This daemon creates and refreshes kerberos tickets, these tickets can be
used to launch new containers.
The gMSA feature can be implemented using this daemon.
Kerberos tickets are refreshed when tickets expire or when a gMSA password changes.
The same method can be used to refresh other types of security tokens.

%prep
%setup -q

%build
mkdir -p build && cd build && cmake ../ && make

%install
# TBD: Install to /usr/bin later
# install -m 0755 daemon/build/src/credentials-fetcherd credentials-fetcherd
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{_bindir}
# ~/rpmbuild/BUILD/credentials-fetcher-0.0.1/build/daemon/src/credentials-fetcherd
cp $RPM_BUILD_DIR/credentials-fetcher-0.0.1/build/daemon/src/credentials-fetcherd $RPM_BUILD_ROOT/%{_bindir}

%files
%{_bindir}/credentials-fetcherd
%license LICENSE
# https://docs.fedoraproject.org/en-US/packaging-guidelines/LicensingGuidelines/
%doc CONTRIBUTING.md NOTICE README.md
# TBD: Fill above files later

%changelog
* Wed Jun 6 2022 Samiullah Mohammed <samiull@amazon.com> - 0.0.1
- Initial commit
