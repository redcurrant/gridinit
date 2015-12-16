Summary: Redcurant init daemon
Name: redcurrant-grid-init
Version: 1.2
Release: 7%{?dist}
BuildRoot: %_topdir/build_install/%{name}-%{version}
License: GPL v3
Packager: Recurrant team
Group: Redcurrant

%define prefix      /usr
%define libdir      %{prefix}/%{_lib}

Source0: %{name}-%{version}.tar.gz
Source1: gridinit.init
Source2: gridinit.sysconfig
Source3: gridinit.conf

# Requires
%if %{?fc20}0 || %{?el7}0
BuildRequires: libevent-devel
%else
BuildRequires: compat-libevent-20-devel >= 2.0.10
%endif
BuildRequires: glib2-devel		>= 2.24.0
BuildRequires: log4c-devel              >= 1.2.0
BuildRequires: git,bison,flex,cmake

%if %{?fc20}0 || %{?el7}0
Requires: libevent
%else
Requires: compat-libevent-20 >= 2.0.10
%endif
Requires: glib2       	     >= 2.24.0
Requires: %{name}-utils       = %{version}
Requires: log4c              >= 1.2.0

Provides: grid-init

AutoReq: no

%description
Redcurrant software storage solution is designed to handle PETA-bytes of
data in a distributed way, data such as: images, videos, documents, emails,
and any other personal unstructured data.
Redcurrant is brought to the community by Atos Worldline.
This package contains Recurrant init solution. It forks processes and respawns
them as soon as they die. It also provides a simple management interface through
a UNIX socket. Services can be started/stopped/monitored.


%package utils
Summary: Redcurrant init utilities library
License: GPL v3
Vendor: ATOS ORIGIN MULTIMEDIA
Packager: Recurrant team
Group: Redcurrant

Requires: glib2          >= 2.24.0
Requires: log4c          >= 1.2.0

Provides: grid-init-utils

%description utils
Redcurrant software storage solution is designed to handle PETA-bytes of
data in a distributed way, data such as: images, videos, documents, emails,
and any other personal unstructured data.
Redcurrant is brought to the community by Atos Worldline.
This package contains C code library with children processes management
features. This library is internally used by the gridinit process.


%prep
rm -rf "${RPM_BUILD_DIR}/%{name}-%{version}"
%setup -q -n gridinit-%{version}


%build
cmake \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DPREFIX=%{prefix} \
        -DGRIDINIT_SOCKET_PATH=/var/run/redcurrant/gridinit.sock \
        .
make


%install
rm -rf "${RPM_BUILD_ROOT}"

make DESTDIR=${RPM_BUILD_ROOT} install

# Default conf and log4crc files
%{__mkdir_p} ${RPM_BUILD_ROOT}/etc
%{__install} gridinit.conf ${RPM_BUILD_ROOT}/etc/gridinit.conf
%{__install} gridinit.log4crc.default ${RPM_BUILD_ROOT}/etc/gridinit.log4crc

# socket/pid files
%{__mkdir_p} ${RPM_BUILD_ROOT}/var/run/redcurrant
%{__mkdir_p} ${RPM_BUILD_ROOT}/GRID/common/

# Add init script
%{__mkdir_p} ${RPM_BUILD_ROOT}/etc/rc.d/init.d ${RPM_BUILD_ROOT}/etc/sysconfig
%{__install} -m 755 %{SOURCE1} ${RPM_BUILD_ROOT}/etc/rc.d/init.d/gridinit
%{__install} %{SOURCE2} ${RPM_BUILD_ROOT}/etc/sysconfig/gridinit
%{__install} %{SOURCE3} ${RPM_BUILD_ROOT}/etc/gridinit.conf

# Remove dirty .la
rm -vf $RPM_BUILD_ROOT%{libdir}/gridinit/*.la


%files
%defattr(-,root,root,-)
/etc/rc.d/init.d/gridinit
%dir %attr(755,admgrid,admgrid) %{_var}/run/redcurrant
%config(noreplace) /etc/sysconfig/gridinit
%config(noreplace) /etc/gridinit.conf
%{prefix}/bin/gridinit*
%config(noreplace) %attr(644,admgrid,admgrid) /etc/gridinit*

%files utils
%defattr(-,root,root,-)
%{prefix}/include/*.h
%{libdir}/libgridinit-utils.*

%post
/sbin/ldconfig
%post utils
/sbin/ldconfig

%postun
/sbin/ldconfig
/bin/ln -s /var/run/redcurrant /GRID/common/run
%postun utils
/sbin/ldconfig

%clean
rm -rf "${RPM_BUILD_ROOT}"
rm -rf "${RPM_BUILD_DIR}/%{name}"

%changelog
* Wed Dec 16 2015 - 1.2-7 - JFS
- Gridinit's children can now inherits gridinit's environement
- Merge pull request #5 from jfsmig/master
- Merge pull request #4 from jfsmig/master
- Got rid of sysmm mentions
- fixed path detection
- Merge pull request #3 from conradkleinespel/patch-1
- fixes logic error when looking for executable file
- Merge pull request #2 from jfsmig/master
- Merge pull request #1 from jfsmig/master
- Locates binaries with the PATH
- cmake: now uses the standard CMAKE_INSTALL_PREFIX
- General cleanup
* Thu Apr 02 2015 - 1.2-6 - Florent Vennetier
- Fix access rights on /var/run/redcurrant
* Wed Nov 12 2014 - 1.2-5 - Franck Perrault
- move binaries from /usr/local/bin to /usr/bin
- add /var/run/redcurrant/
- override gridinit.conf from sources by a more clean gridinit.conf (FHS compliant and wthout ugly private references => to be modified in future git release)
- ugly workaround for gridinit_cmd where path /GRID/common/run/gridinit.sock is hardcoded
- Change socket path in .spec according to new gridinit.conf files
* Thu Nov 06 2014 - 1.2-4 - Franck Perrault
- Amend /etc/init.d/gridinit to read /etc/gridinit.{cong,log4crc} if not found in /GRID usual paths
- Change name for gridinit.conf gridinit.conf.default in /GRID/
- add gridinit.conf.default in /etc
* Thu Nov 06 2014 - 1.2-3 - Remi Nivet
- Change compat-glib2 to glib2 dep (since CentOS 6.6)
* Tue Oct 02 2014 - 1.2-2 - Romain Acciari
- Fix for Fedora 20 and el7
* Fri Jul 11 2014 - 1.2-1 - Remi Nivet
- new version 1.2
* Fri May 24 2013 - 1.1.4-2 - Romain Acciari
- Initial release
