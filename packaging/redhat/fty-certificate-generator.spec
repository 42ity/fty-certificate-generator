#
#    fty-certificate-generator - Generation internal certificates agent
#
#    Copyright (C) 2014 - 2019 Eaton
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

# To build with draft APIs, use "--with drafts" in rpmbuild for local builds or add
#   Macros:
#   %_with_drafts 1
# at the BOTTOM of the OBS prjconf
%bcond_with drafts
%if %{with drafts}
%define DRAFTS yes
%else
%define DRAFTS no
%endif
%define SYSTEMD_UNIT_DIR %(pkg-config --variable=systemdsystemunitdir systemd)
Name:           fty-certificate-generator
Version:        1.0.0
Release:        1
Summary:        generation internal certificates agent
License:        GPL-2.0+
URL:            https://42ity.org
Source0:        %{name}-%{version}.tar.gz
Group:          System/Libraries
# Note: ghostscript is required by graphviz which is required by
#       asciidoc. On Fedora 24 the ghostscript dependencies cannot
#       be resolved automatically. Thus add working dependency here!
BuildRequires:  ghostscript
BuildRequires:  asciidoc
BuildRequires:  automake
BuildRequires:  autoconf
BuildRequires:  libtool
BuildRequires:  pkgconfig
BuildRequires:  systemd-devel
BuildRequires:  systemd
%{?systemd_requires}
BuildRequires:  xmlto
BuildRequires:  gcc-c++
BuildRequires:  log4cplus-devel
BuildRequires:  fty-common-logging-devel
BuildRequires:  openssl-devel
BuildRequires:  fty-lib-certificate-devel
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
fty-certificate-generator generation internal certificates agent.

%package -n libfty_certificate_generator1
Group:          System/Libraries
Summary:        generation internal certificates agent shared library

%description -n libfty_certificate_generator1
This package contains shared library for fty-certificate-generator: generation internal certificates agent

%post -n libfty_certificate_generator1 -p /sbin/ldconfig
%postun -n libfty_certificate_generator1 -p /sbin/ldconfig

%files -n libfty_certificate_generator1
%defattr(-,root,root)
%{_libdir}/libfty_certificate_generator.so.*

%package devel
Summary:        generation internal certificates agent
Group:          System/Libraries
Requires:       libfty_certificate_generator1 = %{version}
Requires:       log4cplus-devel
Requires:       fty-common-logging-devel
Requires:       openssl-devel
Requires:       fty-lib-certificate-devel

%description devel
generation internal certificates agent development tools
This package contains development files for fty-certificate-generator: generation internal certificates agent

%files devel
%defattr(-,root,root)
%{_includedir}/*
%{_libdir}/libfty_certificate_generator.so
%{_libdir}/pkgconfig/libfty_certificate_generator.pc
%{_mandir}/man3/*
%{_mandir}/man7/*

%prep

%setup -q

%build
sh autogen.sh
%{configure} --enable-drafts=%{DRAFTS} --with-systemd-units
make %{_smp_mflags}

%install
make install DESTDIR=%{buildroot} %{?_smp_mflags}

# remove static libraries
find %{buildroot} -name '*.a' | xargs rm -f
find %{buildroot} -name '*.la' | xargs rm -f

%files
%defattr(-,root,root)
%doc README.md
%{_bindir}/fty-certificate-generator
%{_mandir}/man1/fty-certificate-generator*
%config(noreplace) %{_sysconfdir}/fty-certificate-generator/fty-certificate-generator.cfg
%{SYSTEMD_UNIT_DIR}/fty-certificate-generator.service
%dir %{_sysconfdir}/fty-certificate-generator
%if 0%{?suse_version} > 1315
%post
%systemd_post fty-certificate-generator.service
%preun
%systemd_preun fty-certificate-generator.service
%postun
%systemd_postun_with_restart fty-certificate-generator.service
%endif

%changelog
