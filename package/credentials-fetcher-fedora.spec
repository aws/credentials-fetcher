%global major_version 0
%global minor_version 0
%global patch_version 94

# For handling bump release by rpmdev-bumpspec and mass rebuild
%global baserelease 1

Name:           credentials-fetcher
Version:        %{major_version}.%{minor_version}.%{patch_version}
Release:        %{baserelease}%{?dist}
Summary:        credentials-fetcher is a daemon that refreshes tickets or tokens periodically

License:        Apache-2.0
URL:            https://github.com/aws/credentials-fetcher
Source0:        https://github.com/aws/credentials-fetcher/archive/refs/tags/%{version}.tar.gz

BuildRequires:  cmake3 make chrpath openldap-devel grpc-devel

Requires: bind-utils openldap mono-core openldap-clients

# https://docs.fedoraproject.org/en-US/packaging-guidelines/CMake/

%description
This daemon creates and refreshes kerberos tickets, these tickets can be
used to launch new containers.
The gMSA feature can be implemented using this daemon.
Kerberos tickets are refreshed when tickets expire or when a gMSA 
password changes. The same method can be used to refresh other types 
of security tokens. This spec file is specific to Fedora, use this file 
to rpmbuild on Fedora.

%prep
%setup -q

%build
%cmake3
%cmake_build

%install

%cmake_install
# https://docs.fedoraproject.org/en-US/packaging-guidelines/#_removing_rpath
# https://docs.fedoraproject.org/en-US/packaging-guidelines/#_rpath_for_internal_libraries
chrpath --delete %{buildroot}/%{_sbindir}/credentials-fetcherd

%check
# TBD: Run tests from top-level directory
ctest3

%files
%{_sbindir}/credentials-fetcherd
%{_unitdir}/credentials-fetcher.service
%license LICENSE
# https://docs.fedoraproject.org/en-US/packaging-guidelines/LicensingGuidelines/
%doc CONTRIBUTING.md NOTICE README.md
%attr(0700, -, -) %{_sbindir}/credentials_fetcher_utf16_private.exe

%changelog
* Mon Aug 29 2022 Tom Callaway <spotaws@amazon.com> - 0.0.94-1
- systemd clean up
* Mon Aug 22 2022 Sai Kiran Akula <saakla@amazon.com> - 0.0.93
- Add validation for read metadata file and rpm install require openldap-clients
* Wed Aug 10 2022 Samiullah Mohammed <samiull@amazon.com> - 0.0.92
- Move binaries to standard Linux directories
- Add directory paths as configurable variables in cmake
- Generate systemd service file from cmake
* Sun Aug 7 2022 Samiullah Mohammed <samiull@amazon.com> - 0.0.91
- Relocate binary, library files and change permissions
* Sat Jul 30 2022 Samiullah Mohammed <samiull@amazon.com> - 0.0.90
- add ctests and bump revision to 0.0.90
* Thu Jul 28 2022 Samiullah Mohammed <samiull@amazon.com> - 0.0.1
- Add mono-based utf16 decoder
* Tue Jul 12 2022 Samiullah Mohammed <samiull@amazon.com> - 0.0.1
- Resolve rpath for Fedora and change macros
* Sat Jun 18 2022 Sai Kiran Akula <saakla@amazon.com> - 0.0.1
- Refactor cmake for all the directories
* Thu Jun 16 2022 Samiullah Mohammed <samiull@amazon.com> - 0.0.1
- Compile subdirectory into a shared library
* Wed Jun 15 2022 Samiullah Mohammed <samiull@amazon.com> - 0.0.1
- Add daemon infra
* Wed Jun 8 2022 Samiullah Mohammed <samiull@amazon.com> - 0.0.1
- Fixes to rpm spec
* Mon Jun 6 2022 Samiullah Mohammed <samiull@amazon.com> - 0.0.1
- Initial commit
