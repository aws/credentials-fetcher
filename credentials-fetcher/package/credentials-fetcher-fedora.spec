Name:           credentials-fetcher
Version:        0.0.1
Release:        1%{?dist}
Summary:        credentials-fetcher is a daemon that refreshes tickets or tokens periodically

License:        Apache 2.0
URL:            tbd-project.com
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cmake3 make chrpath

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
cd %{_builddir}/credentials-fetcher-0.0.1/daemon/ && ctest3

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

%changelog
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
