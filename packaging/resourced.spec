Name:       resourced
Summary:    System Resource Daemon
Version:    0.0.1
Release:    1
Group:      System/Management
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    resourced.service
Source2:    resourcedperday.service
Source3:    resourcedperday.timer
Source4:    resourcedswapfile.service
Source5:    resourced_swapoff.service
Source6:    resourced-cpucgroup.service

%define powertop_state ON
%define cpu_module ON
%define memory_eng ON
%define swap_state ON
%define exclude_list_opt_full_path /opt/usr/etc/_exclude_list_file_name_
%define datausage_state ON
%define database_full_path /opt/usr/dbspace/.resourced-datausage.db

BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(vconf-internal-keys)
%if %{?datausage_state} == ON
BuildRequires:  pkgconfig(capi-telephony-network-info)
BuildRequires:  pkgconfig(network)
%endif
BuildRequires:  pkgconfig(ecore)
BuildRequires:  pkgconfig(x11)
BuildRequires:  pkgconfig(ecore-x)
BuildRequires:  pkgconfig(utilX)
BuildRequires:  pkgconfig(ecore-input)
BuildRequires:  pkgconfig(ecore-file)
BuildRequires:  pkgconfig(edbus)
BuildRequires:  pkgconfig(appcore-common)
BuildRequires:  pkgconfig(appcore-efl)
BuildRequires:  pkgconfig(elementary)
BuildRequires:  pkgconfig(vconf)

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

%if %{?powertop_state} == ON
%package powertop-wrapper
Summary: Powertop-wrapper libray
Group:   System/Libraries

%description powertop-wrapper
Powertop control library
%endif

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

cmake . -DCMAKE_INSTALL_PREFIX=/usr -DFULLVER=%{version} -DMAJORVER=${MAJORVER} -DCMAKE_BUILD_TYPE=Release \
	-DEXCLUDE_LIST_OPT_FULL_PATH=%{exclude_list_opt_full_path} -DSWAP_MODULE=%{swap_state} \
	-DPOWERTOP_MODULE=%{powertop_state} \
	-DCPU_MODULE=%{cpu_module} \
	-DMEMORY_ENG=%{memory_eng}\
	-DDATAUSAGE_MODULE=%{datausage_state} \
	-DDATABASE_FULL_PATH=%{database_full_path}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp -f LICENSE %{buildroot}/usr/share/license/%{name}

%if %{?powertop_state} == ON
cp -f LICENSE %{buildroot}/usr/share/license/%{name}-powertop-wrapper
%endif

%make_install

%if %{?datausage_state} == ON
	mkdir -p %{buildroot}/opt/usr/dbspace
	sqlite3 %{buildroot}%{database_full_path} < %{buildroot}/usr/share/traffic_db.sql
	rm %{buildroot}/usr/share/traffic_db.sql
%endif

mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants

%if %{?swap_state} == ON
install -m 0644 %SOURCE1 %{buildroot}%{_libdir}/systemd/system/resourced.service
ln -s ../resourced.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/resourced.service

install -m 0644 %SOURCE2 %{buildroot}%{_libdir}/systemd/system/resourcedperday.service
ln -s ../resourcedperday.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/resourcedperday.service
install -m 0644 %SOURCE3 %{buildroot}%{_libdir}/systemd/system/resourcedperday.timer
ln -s ../resourcedperday.timer %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/resourcedperday.timer

mkdir -p %{buildroot}%{_libdir}/systemd/system/graphical.target.wants
install -m 0644 %SOURCE4 %{buildroot}%{_libdir}/systemd/system/resourcedswapfile.service
ln -s ../resourcedswapfile.service %{buildroot}%{_libdir}/systemd/system/graphical.target.wants/resourcedswapfile.service
%else
install -m 0644 %SOURCE5 %{buildroot}%{_libdir}/systemd/system/resourced.service
ln -s ../resourced.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/resourced.service
%endif

%if %{?cpu_module} == OFF
mkdir -p %{buildroot}%{_libdir}/systemd/system/graphical.target.wants
install -m 0644 %SOURCE2 %{buildroot}%{_libdir}/systemd/system/resourced-cpucgroup.service
ln -s ../resourced-cpucgroup.service %{buildroot}%{_libdir}/systemd/system/graphical.target.wants/resourced-cpucgroup.service
%endif

#powertop-wrapper part
%if %{?powertop_state} == ON
mkdir -p %{buildroot}/usr/share/powertop-wrapper/
cp -p %_builddir/%name-%version/src/powertop-wrapper/header.html %{buildroot}/usr/share/powertop-wrapper
%endif

%post -p /sbin/ldconfig

mkdir -p /opt/usr/etc

if [ "$1" = "2" ]; then # upgrade begins
	systemctl start resourced.service
fi

%postun -p /sbin/ldconfig

%if %{?powertop_state} == ON
%post powertop-wrapper -p /sbin/ldconfig
%postun powertop-wrapper -p /sbin/ldconfig
%endif

%files
%manifest resourced.manifest
%{_libdir}/libproc-stat.so.*
/usr/share/license/%{name}
%attr(-,root, root) %{_bindir}/resourced
%config %{_sysconfdir}/dbus-1/system.d/resourced.conf
%{_libdir}/systemd/system/resourced.service
%{_libdir}/systemd/system/multi-user.target.wants/resourced.service
%config /etc/resourced/memory.conf
%{_libdir}/libresourced.so.*
%{_libdir}/librd-network.so.*
%{_bindir}/memps
%if %{?datausage_state} == ON
    %config(noreplace) %attr(660,root,app) %{database_full_path}
    %config(noreplace) %attr(660,root,app) %{database_full_path}-journal
%endif

%if %{?swap_state} == ON
%{_libdir}/systemd/system/resourcedperday.service
%{_libdir}/systemd/system/multi-user.target.wants/resourcedperday.service
%{_libdir}/systemd/system/resourcedperday.timer
%{_libdir}/systemd/system/multi-user.target.wants/resourcedperday.timer
%{_libdir}/systemd/system/resourcedswapfile.service
%{_libdir}/systemd/system/graphical.target.wants/resourcedswapfile.service
%endif

%if %{?powertop_state} == ON
%files powertop-wrapper
%manifest powertop-wrapper.manifest
%{_libdir}/libpowertop-wrapper.so.*
/usr/share/powertop-wrapper/header.html
/usr/share/license/%{name}-powertop-wrapper
%endif

#memps
%attr(-,root, root) %{_bindir}/memps

%config  /etc/resourced/cpu.conf

%files devel
%{_libdir}/pkgconfig/*.pc
%{_includedir}/system/proc_stat.h
%{_libdir}/libproc-stat.so
%{_includedir}/system/resourced.h
%{_includedir}/system/data_usage.h
%{_includedir}/system/rd-network.h
%{_libdir}/libresourced.so
%{_libdir}/librd-network.so

%if %{?powertop_state} == ON
#powertop-wrapper part
%{_includedir}/system/powertop-dapi.h
%{_libdir}/libpowertop-wrapper.so
%endif
