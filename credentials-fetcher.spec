# RPM spec file for credentials-fetcher opensource build
%global debug_package %{nil}

%global major_version 2
%global minor_version 0
%global patch_version 0

Name:           credentials-fetcher
Version:        %{major_version}.%{minor_version}.%{patch_version}
Release:        1%{?dist}
License:        Apache 2.0
Summary:        Credentials Fetcher Service is used to connect to Active Directory from Linux Instances
URL:            https://github.com/aws/credentials-fetcher
Source:         %{name}-%{version}-src.tar.gz

# Runtime requirements
Requires:       openldap-clients
Requires:       krb5-workstation
Requires:       sssd

# Build requirements for Go compilation
BuildRequires:  make
BuildRequires:  krb5-devel

# Conditional dependencies based on OS version
%if 0%{?is_al2023}
BuildRequires:  glibc-devel
%else
BuildRequires:  glibc-static
%endif

# Required for systemd macros
%if 0%{?fedora} || 0%{?rhel} >= 8 || 0%{?is_al2023}
BuildRequires:  systemd-rpm-macros
%endif

# Define _unitdir if not already defined
%{!?_unitdir: %global _unitdir /usr/lib/systemd/system}

# Following are needed to prevent RPM build errors
%define _missing_build_ids_terminate_build 0
%define debug_package %{nil}
%define SERVICE_NAME credentials-fetcher.service

%description
credentials-fetcher is a daemon that refreshes tickets or tokens periodically.
This is the Golang refactor of the original credentials-fetcher.

%prep
# This extracts the source during RPM generation
%setup -q -n %{name}-%{version}-src

%build
# Build using the opensource Makefile
cd opensource
make build VERSION=%{version}

%install
rm -rf ${RPM_BUILD_ROOT}

# Create directory structure in buildroot
mkdir -p %{buildroot}/usr/sbin
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}/var/credentials-fetcher/{krbdir,socket,logging}
mkdir -p %{buildroot}/etc/

# Copy binary and service file to buildroot
cp ./opensource/bin/credentials-fetcherd %{buildroot}/usr/sbin/credentials-fetcher
cp ./configuration/bin/credentials-fetcher.service %{buildroot}%{_unitdir}/

# Copy config files to buildroot
cp ./configuration/conf/credentials-fetcher.conf %{buildroot}/etc/
cp ./configuration/conf/krb5.conf %{buildroot}/etc/

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
/usr/sbin/credentials-fetcher
%config(noreplace) /etc/credentials-fetcher.conf
%config(noreplace) /etc/krb5.conf
%{_unitdir}/credentials-fetcher.service
%dir /var/credentials-fetcher
%dir /var/credentials-fetcher/krbdir
%dir /var/credentials-fetcher/socket
%dir /var/credentials-fetcher/logging

%post
chmod 644 %{_unitdir}/%{SERVICE_NAME}
/usr/bin/systemctl daemon-reload

%postun
/usr/bin/systemctl daemon-reload

%changelog
* Fri Jan 09 2026 Muskan Lalit <muskanl@amazon.com> - 2.0.0
- Initial RPM release for CredentialsFetcherV2 
