%global major_version 0
%global minor_version 0
%global patch_version 90

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

BuildRequires:  cmake3 make chrpath

Requires: bind-utils openldap mono-core

%description
This daemon creates and refreshes kerberos tickets, these tickets can be
used to launch new containers.
The gMSA feature can be implemented using this daemon.
Kerberos tickets are refreshed when tickets expire or when a gMSA password changes.
The same method can be used to refresh other types of security tokens.
This spec file is specific to Fedora, use this file to rpmbuild on Fedora.


# https://docs.fedoraproject.org/en-US/packaging-guidelines/CMake/
%prep
%setup -q

%build
%cmake3
%cmake_build

%install

%cmake_install
# https://docs.fedoraproject.org/en-US/packaging-guidelines/#_removing_rpath
# https://docs.fedoraproject.org/en-US/packaging-guidelines/#_rpath_for_internal_libraries
chrpath -r /usr/lib64/credentials-fetcher %{buildroot}/usr/sbin/credentials-fetcherd

%check
# TBD: Run tests from top-level directory
ctest3

%files
%{_sbindir}/credentials-fetcherd
%{_sysconfdir}/systemd/system/credentials-fetcher.service
%license LICENSE
%config /etc/credentials-fetcher/config.json
%{_sysconfdir}/credentials-fetcher/env-file
# https://docs.fedoraproject.org/en-US/packaging-guidelines/LicensingGuidelines/
%doc CONTRIBUTING.md NOTICE README.md
%{_localstatedir}/log/credentials-fetcher/.ignore
%{_datadir}/credentials-fetcher/.ignore
%{_sysconfdir}/credentials-fetcher/.ignore
%attr(0755, -, -) /usr/lib64/credentials-fetcher/libcf-sources.so
%attr(0755, -, -) /usr/lib64/credentials-fetcher/libcf-gmsa-service.so
%attr(0755, -, -) /usr/lib64/credentials-fetcher/decode.exe

%changelog
* Sat Jul 30 2022 Samiullah Mohammed <samiull@amazon.com>
- add ctests and bump revision to 0.0.90  - 0.0.90
* Thu Jul 28 2022 Samiullah Mohammed <samiull@amazon.com>
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
