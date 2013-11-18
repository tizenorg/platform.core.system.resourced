Name:       resourced
Summary:    System Resource Daemon
Version:    0.0.1
Release:    1
Group:      System/Management
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    resourced.service

BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(vconf-internal-keys)
BuildRequires:  pkgconfig(ecore)
BuildRequires:  pkgconfig(x11)
BuildRequires:  pkgconfig(ecore-x)
BuildRequires:  pkgconfig(utilX)
BuildRequires:  pkgconfig(ecore-input)
BuildRequires:  pkgconfig(ecore-file)
BuildRequires:  pkgconfig(edbus)

Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
System Resource Daemon to manage memory and process state

%package devel
Summary:  System Resource Information (Development)
Group:    System/Development
Requires: %{name} = %{version}-%{release}

%description devel
Development package for Resourced Daemon
to manage memory and process state

%prep
%setup -q

%build
MAJORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $1}'`
MINORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $2}'`
PATCHVER=`echo %{version} | awk 'BEGIN {FS="."}{print $3}'`
echo "\
/* That file was generated automaticaly. Don't edit it */
#define MINOR_VERSION ${MINORVER}
#define MAJOR_VERSION ${MAJORVER}
#define PATCH_VERSION ${PATCHVER}" > src/common/version.h

%if 0%{?tizen_build_binary_release_type_eng}
	CFLAGS+=" -DTIZEN_ENGINEER_MODE"
%endif

cmake . -DCMAKE_INSTALL_PREFIX=/usr -DFULLVER=%{version} -DMAJORVER=${MAJORVER} -DCMAKE_BUILD_TYPE=Release

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp -f LICENSE %{buildroot}/usr/share/license/%{name}

%make_install

mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants
install -m 0644 %SOURCE1 %{buildroot}%{_libdir}/systemd/system/resourced.service
ln -s ../resourced.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/resourced.service

%post -p /sbin/ldconfig

mkdir -p /opt/usr/etc

if [ "$1" = "2" ]; then # upgrade begins
	systemctl start resourced.service
fi

%postun -p /sbin/ldconfig

%files
%manifest resourced.manifest
%{_libdir}/libproc-stat.so.*
/usr/share/license/%{name}
%attr(-,root, root) %{_bindir}/resourced
%config %{_sysconfdir}/dbus-1/system.d/resourced.conf
%{_libdir}/systemd/system/resourced.service
%{_libdir}/systemd/system/multi-user.target.wants/resourced.service
%config /etc/resourced/memory.conf

%files devel
%{_libdir}/pkgconfig/*.pc
%{_includedir}/system/proc_stat.h
%{_libdir}/libproc-stat.so
%{_includedir}/system/resourced.h
