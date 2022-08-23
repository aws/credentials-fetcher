%global major_version 0
%global minor_version 0
%global patch_version 93

# Set to RC version if building RC, else %%{nil}
%global rcsuf rc2
%{?rcsuf:%global relsuf .%{rcsuf}}
%{?rcsuf:%global versuf -%{rcsuf}}

# For handling bump release by rpmdev-bumpspec and mass rebuild
%global baserelease 0.2

Name:           credentials-fetcher
Version:        %{major_version}.%{minor_version}.%{patch_version}
Release:        %{baserelease}%{?relsuf}%{?dist}
Summary:        credentials-fetcher is a daemon that refreshes tickets or tokens periodically

License:        Apache 2.0
URL:            tbd-project.com
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cmake3 make

Requires: bind-utils openldap mono-core openldap-clients

%description
This daemon creates and refreshes kerberos tickets, these tickets can be
used to launch new containers.
The gMSA feature can be implemented using this daemon.
Kerberos tickets are refreshed when tickets expire or when a gMSA password changes.
The same method can be used to refresh other types of security tokens.

%prep
%setup -q

%build
%cmake3
%make_build

%make_install

%check
# TBD: Run tests from top-level directory
ctest3

%files
/usr/sbin/credentials-fetcherd
%{_sysconfdir}/systemd/system/credentials-fetcher.service
%license LICENSE
%config /etc/credentials-fetcher/config.json
%config /etc/credentials-fetcher/env-file
# https://docs.fedoraproject.org/en-US/packaging-guidelines/LicensingGuidelines/
%doc CONTRIBUTING.md NOTICE README.md

%changelog
* Mon Aug 22 2022 Sai Kiran Akula <saakla@amazon.com> - 0.0.93
- Add validation for read metadata file and rpm install require openldap-clients
* Tue Aug  9 Samiullah Mohammed <samiull@amazon.com> - 0.0.92
- Move binaries to standard Linux directories
* Sat Aug 7 2022 Samiullah Mohammed <samiull@amazon.com> - 0.0.91
- Relocate binary, library files and change permissions
* Sat Jul 30 2022 Samiullah Mohammed <samiull@amazon.com> - 0.0.90
- add ctests and bump revision to 0.0.90
* Thu Jul 28 2022 Samiullah Mohammed <samiull@amazon.com> - 0.0.1
- Add mono-based utf16 decoder
* Mon Jul 25 2022 Samiullah Mohammed <samiull@amazon.com> - 0.0.1
- Add openldap as a requirement, also added crypto lib
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
