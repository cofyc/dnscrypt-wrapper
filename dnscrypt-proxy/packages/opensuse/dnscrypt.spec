#
# spec file for package dnscrypt
#
# Copyright (c) 2012 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#

Name:           dnscrypt
Version:	1.2.0
Release:	0
License:	BSD-3-Clause
Summary:	A tool for securing communications between a client and a DNS resolver
Url:	https://github.com/opendns/dnscrypt
Group:  Productivity/Networking/DNS/Utilities
Source:	%{name}-proxy-%{version}.tar.bz2
Source1:	%{name}.service
%if 0%{?suse_version} >= 1210
BuildRequires:	systemd
%{?systemd_requires}
%endif
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
dnscrypt-proxy provides local service which can be used directly as your local resolver or as a DNS forwarder, 
encrypting and authenticating requests using the DNSCrypt protocol and passing them to an upstream server, 
by default OpenDNS who run this on their resolvers.

The DNSCrypt protocol uses high-speed high-security elliptic-curve cryptography and is very similar to 
DNSCurve, but focuses on securing communications between a client and its first-level resolver.

While not providing end-to-end security, it protects the local network, which is often the weakest point 
of the chain, against man-in-the-middle attacks. It also provides some confidentiality to DNS queries.

%prep
%setup -q -n %{name}-proxy-%{version}

%build
%configure
make %{?_smp_mflags}

%install
%make_install

# install systemd service
mkdir -p %{buildroot}%{_unitdir}
cp -r %{SOURCE1} %{buildroot}%{_unitdir}

%if 0%{?suse_version}
%pre
%service_add_pre %{name}.service

%post
%service_add_post %{name}.service

%preun
%service_del_preun %{name}.service

%postun
%service_del_postun %{name}.service
%endif

%files
%defattr(-,root,root)
%doc AUTHORS ChangeLog README COPYING NEWS TECHNOTES THANKS
%{_bindir}/hostip
%{_sbindir}/%{name}-proxy
%{_unitdir}/%{name}.service
%{_mandir}/man8/hostip.8.gz
%{_mandir}/man8/%{name}-proxy.8.gz

%changelog

