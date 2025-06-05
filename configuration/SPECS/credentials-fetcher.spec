%global debug_package %{nil}

# Version can be overridden at build time:
# rpmbuild -ba --define "version 2.0.1" --define "release 1" credentials-fetcher.spec
%{!?version: %global version 2.0.0}
%{!?release: %global release 1}

Name:           credentials-fetcher
Version:        %{version}
Release:        %{release}%{?dist}
Summary:        Credentials Fetcher Service for AWS
License:        Apache-2.0
URL:            https://code.amazon.com/packages/CredentialsFetcherV2
Source0:        %{name}-%{version}.tar.gz

# If systemd-rpm-macros is not available, you can create a custom package
# See README.md for instructions on creating a custom systemd-rpm-macros package
BuildRequires:  golang >= 1.18
BuildRequires:  systemd-devel

Requires:       openldap-clients
Requires:       krb5-workstation
Requires:       sssd

%description
credentials-fetcher is a daemon that refreshes tickets or tokens periodically
This is the Golang refactor of the original credentials-fetcher.

%prep
%setup -q

%build
go build -v -o bin/credentials-fetcherd cmd/credentials-fetcher/main.go

%install
# Create directories
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_sysconfdir}/credentials-fetcher
mkdir -p %{buildroot}%{_localstatedir}/credentials-fetcher/{krbdir,socket,logging}

# Install binary
install -p -m 755 bin/credentials-fetcherd %{buildroot}%{_bindir}/credentials-fetcher

# Install systemd service file
install -p -m 644 service/credentials-fetcher.service %{buildroot}%{_unitdir}/

# Set permissions for directories
chmod 755 %{buildroot}%{_localstatedir}/credentials-fetcher
chmod 755 %{buildroot}%{_localstatedir}/credentials-fetcher/krbdir
chmod 755 %{buildroot}%{_localstatedir}/credentials-fetcher/socket
chmod 755 %{buildroot}%{_localstatedir}/credentials-fetcher/logging

%pre
getent group credentials-fetcher >/dev/null || groupadd -r credentials-fetcher
getent passwd credentials-fetcher >/dev/null || \
    useradd -r -g credentials-fetcher -d %{_localstatedir}/credentials-fetcher -s /sbin/nologin \
    -c "Credentials Fetcher Service" credentials-fetcher
exit 0

%post
%systemd_post credentials-fetcher.service

%preun
%systemd_preun credentials-fetcher.service

%postun
%systemd_postun_with_restart credentials-fetcher.service

%files
%license LICENSE
%doc README.md
%{_bindir}/credentials-fetcher
%{_unitdir}/credentials-fetcher.service
%dir %{_sysconfdir}/credentials-fetcher
%dir %{_localstatedir}/credentials-fetcher
%dir %{_localstatedir}/credentials-fetcher/krbdir
%dir %{_localstatedir}/credentials-fetcher/socket
%dir %{_localstatedir}/credentials-fetcher/logging

%changelog
* Wed Jun 05 2025 Saksham Bhalla <sakshmb@amazon.com> - %{version}-%{release}
- Initial RPM release of CredentialsFetcherV2
- Support for dynamic versioning in CI/CD pipeline
