# RPM spec file for credentials-fetcher opensource build
%global debug_package %{nil}

%global major_version 2
%global minor_version 0
%global patch_version 1

Name: credentials-fetcher
Version: %{major_version}.%{minor_version}.%{patch_version}
Release: 1%{?dist}
License: Apache 2.0
Summary: Credentials Fetcher Service is used to connect to Active Directory from Linux Instances
URL: https://github.com/aws/credentials-fetcher
Source: %{name}-%{version}-src.tar.gz

# Runtime requirements
Requires: openldap-clients
Requires: krb5-workstation
Requires: sssd

# Build requirements for Go compilation
BuildRequires: make
BuildRequires: krb5-devel

# Conditional dependencies based on OS version
%if 0%{?is_al2023}
BuildRequires: glibc-devel
%else
BuildRequires: glibc-static
%endif

# Required for systemd macros
%if 0%{?fedora} || 0%{?rhel} >= 8 || 0%{?is_al2023}
BuildRequires: systemd-rpm-macros
%endif

# Define _unitdir if not already defined
%{!?_unitdir: %global _unitdir /usr/lib/systemd/system}

# Define _libexec if not already defined
%{!?_libexec: %global _libexec /usr/libexec}

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
make build VERSION=%{version}

%install
rm -rf ${RPM_BUILD_ROOT}

# Create directory structure in buildroot
mkdir -p %{buildroot}/usr/sbin
mkdir -p %{buildroot}%{_unitdir}/ecs.service.d
mkdir -p %{buildroot}/var/credentials-fetcher/{krbdir,socket,logging}
mkdir -p %{buildroot}/etc/
mkdir -p %{buildroot}%{_libexec}

# Copy binary and service file to buildroot
cp ./opensource/bin/credentials-fetcherd %{buildroot}/usr/sbin/credentials-fetcher
cp ./configuration/bin/credentials-fetcher.service %{buildroot}%{_unitdir}/
cp ./configuration/bin/ecs-require-credentials-fetcher.conf %{buildroot}%{_unitdir}/ecs.service.d/

# Copy startup-order userdata script into libexec
cp ./scripts/credentials-fetcher-startup-order.sh %{buildroot}%{_libexec}/

# Copy config files to buildroot
cp ./configuration/conf/credentials-fetcher.conf %{buildroot}/etc/
# Place krb5.conf in /usr/sbin to avoid conflict with system krb5-libs package
cp ./configuration/conf/krb5.conf %{buildroot}/usr/sbin/krb5.conf

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
/usr/sbin/credentials-fetcher
/usr/sbin/krb5.conf
%config(noreplace) /etc/credentials-fetcher.conf
%{_unitdir}/credentials-fetcher.service
%{_unitdir}/ecs.service.d/ecs-require-credentials-fetcher.conf
%dir /var/credentials-fetcher
%dir /var/credentials-fetcher/krbdir
%dir /var/credentials-fetcher/socket
%dir /var/credentials-fetcher/logging
%{_libexec}/credentials-fetcher-startup-order.sh

%post
chmod 644 %{_unitdir}/%{SERVICE_NAME}
/usr/bin/systemctl daemon-reload
# Since `ecs.service` gets a new dependency on `credentials-fetcher.service`, it stops on the initial reload. Start it back up if enabled
/usr/bin/systemctl is-enabled --quiet ecs.service 2>/dev/null && /usr/bin/systemctl restart ecs.service || :

%postun
/usr/bin/systemctl daemon-reload
# If this is a full removal, and *NOT* an upgrade:
if [ $1 -eq 0 ]; then
    # If the user ran our systemd dependency script, there will be an out-of-package systemd drop-in for ECS agent.
    # Remove this, and also clean up the drop-in directory, but only if it is empty after removing ours.
    if [ -d "/usr/lib/systemd/system/ecs.service.d" ]; then
        rm /usr/lib/systemd/system/ecs.service.d/require-credentials-fetcher.conf
        if [ -z "$( ls -A '/usr/lib/systemd/system/ecs.service.d' )" ]; then
            rm -rf /usr/lib/systemd/system/ecs.service.d
        fi
    fi
    # Service continues running after a full removal, so stop it
    /usr/bin/systemctl stop credentials-fetcher.service
fi

%changelog
* Mon Feb 23 2026 Samiullah Mohammed <samiull@amazon.com> - 2.0.1
- Update ticket renewal logic to fetch username from secret

* Fri Feb 13 2026 Wayne Galen <lewayne@amazon.com> - 2.0.0-1
- Add startup ordering fixup script, to be called from userdata
- New `/docs` directory, to be populated further later
- Fix minor issue where service stays running after an uninstall

* Wed Jan 28 2026 Muskan Lalit <muskanl@amazon.com> - 2.0.0
- credentials-fetcher Golang Release
