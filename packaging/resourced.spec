Name:       resourced
Summary:    System Resource Management Daemon
Version:    0.2.86
Release:    0
Group:      System/Libraries
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz

%define powertop_state OFF
%define cpu_module ON
%define timer_slack OFF

%define vip_agent_module ON

%define logging_module ON
%define logging_memory OFF
%define logging_cpu ON

%define memory_module ON
%define swap_module OFF
%define memory_vmpressure ON

%define network_state OFF
%define tethering_feature OFF

%if "%{?tizen_profile_name}" == "mobile"
	%define swap_module OFF
	%define memory_vmpressure OFF
	%define network_state OFF
	%define tethering_feature OFF
%endif

%if "%{?tizen_profile_name}" == "wearable"
	%define swap_module ON
	%define memory_vmpressure ON
	%define network_state OFF
%endif

%if "%{?tizen_profile_name}" == "tv"
	%define swap_module ON
	%define memory_vmpressure ON
	%define network_state OFF
	%define tethering_feature OFF
%endif

%if 0%{?tizen_build_binary_release_type_eng}
	%define memory_eng ON
%else
	%define memory_eng OFF
%endif

%define exclude_list_file_name resourced_proc_exclude.ini
%define exclude_list_full_path /usr/etc/%{exclude_list_file_name}
%define exclude_list_opt_full_path /opt/usr/etc/%{exclude_list_file_name}
%define database_full_path /opt/usr/dbspace/.resourced-datausage.db

BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(vconf-internal-keys)
BuildRequires:  pkgconfig(ecore)
BuildRequires:  pkgconfig(ecore-file)
BuildRequires:  pkgconfig(eina)
BuildRequires:  pkgconfig(edbus)
BuildRequires:  pkgconfig(libsystemd-daemon)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(bundle)
#only for data types
BuildRequires:  pkgconfig(tapi)
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%if %{?logging_module} == ON
BuildRequires:  pkgconfig(libsystemd-journal)
%endif

%description
Resourced daemon

%package resourced
Summary: Resource Daemon
Group:   System/Libraries

%description resourced
Resource management daemon for memory management and process management (vip processes)

%package -n libresourced
Summary: Resource Daemon Library
Group:   System/Libraries
Requires:   %{name} = %{version}-%{release}

%description -n libresourced
Library for resourced (Resource Management Daemon)

%package -n libresourced-devel
Summary: Resource Daemon Library (Development)
Group:   System/Libraries
Requires:   libresourced  = %{version}-%{release}

%description -n libresourced-devel
Library (development) for resourced (Resource Management Daemon)

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

export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"

%cmake . \
	-DFULLVER=%{version} \
	-DMAJORVER=${MAJORVER} \
	-DCMAKE_BUILD_TYPE=Release \
	-DEXCLUDE_LIST_FILE_NAME=%{exclude_list_file_name} \
	-DEXCLUDE_LIST_FULL_PATH=%{exclude_list_full_path} \
	-DEXCLUDE_LIST_OPT_FULL_PATH=%{exclude_list_opt_full_path} \
	-DVIP_AGENT=%{vip_agent_module} \
	-DSWAP_MODULE=%{swap_module} \
	-DMEMORY_ENG=%{memory_eng} \
	-DMEMORY_VMPRESSURE=%{memory_vmpressure} \
	-DMEMORY_MODULE=%{memory_module} \
	-DMEMORY_VMPRESSURE=%{memory_vmpressure} \
	-DDATABASE_FULL_PATH=%{database_full_path} \
	-DNETWORK_MODULE=%{network_state} \
	-DTELEPHONY_FEATURE=%{telephony_feature} \
	-DDATAUSAGE_TYPE=NFACCT \
	-DLOGGING_MODULE=%{logging_module} \
	-DLOGGING_MEMORY=%{logging_memory} \
	-DLOGGING_CPU=%{logging_cpu} \
	-DPOWERTOP_MODULE=%{powertop_state} \
	-DCPU_MODULE=%{cpu_module} \
	-DTIMER_SLACK=%{timer_slack}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp -f LICENSE %{buildroot}/usr/share/license/%{name}
cp -f LICENSE %{buildroot}/usr/share/license/libresourced

%make_install

%install_service multi-user.target.wants resourced.service
%if %{?swap_module} == ON
%install_service graphical.target.wants resourced-zram.service
%endif

%if %{?network_state} == ON
	mkdir -p %{buildroot}/opt/usr/dbspace
	sqlite3 %{buildroot}%{database_full_path} < %{buildroot}/usr/share/traffic_db.sql
	rm %{buildroot}/usr/share/traffic_db.sql
%endif

mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants

#powertop-wrapper part
%if %{?powertop_state} == ON
mkdir -p %{buildroot}/usr/share/powertop-wrapper/
cp -p %_builddir/%name-%version/src/powertop-wrapper/header.html %{buildroot}/usr/share/powertop-wrapper
%endif

%pre resourced
if [ "$1" = "2" ]; then # upgrade begins
	systemctl stop resourced.service
fi

%post -p /sbin/ldconfig

%post resourced

init_vconf()
{
	vconftool set -t bool db/private/resourced/wifi_statistics 1 -i -f -s tizen::vconf::platform::rw
	vconftool set -t bool db/private/resourced/datacall 1 -i -f -s tizen::vconf::platform::rw
	vconftool set -t bool db/private/resourced/datacall_logging 1 -i -f -s tizen::vconf::platform::rw
	vconftool set -t int db/private/resourced/datausage_timer 60 -i -f -s tizen::vconf::platform::rw
	vconftool set -t string db/private/resourced/new_limit "" -u 5000 -f -s tizen::vconf::platform::rw
	vconftool set -t string db/private/resourced/delete_limit "" -u 5000 -f -s tizen::vconf::platform::rw
	vconftool set -t int db/private/resourced/network_db_entries 0 -i -f -s tizen::vconf::platform::rw
}

%if %{?network_state} == ON
	init_vconf
%endif
#install init.d script
mkdir -p /opt/usr/etc
#make empty dynamic exclude list for first installation
touch %{exclude_list_opt_full_path}

if [ "$1" = "2" ]; then # upgrade begins
	systemctl start resourced.service
fi

%postun -p /sbin/ldconfig

%files -n resourced
/usr/share/license/%{name}
%attr(-,root, root) %{_bindir}/resourced
%if %{?network_state} == ON
	%config(noreplace) %attr(660,root,app) %{database_full_path}
	%config(noreplace) %attr(660,root,app) %{database_full_path}-journal
	/usr/bin/datausagetool
	%config /etc/resourced/network.conf
	/etc/opt/upgrade/500.resourced-datausage.patch.sh
	%attr(700,root,root) /etc/opt/upgrade/500.resourced-datausage.patch.sh
%endif

%manifest resourced.manifest
%config %{_sysconfdir}/dbus-1/system.d/resourced.conf
%{_unitdir}/resourced.service
%{_unitdir}/multi-user.target.wants/resourced.service
%config /etc/resourced/memory.conf
%config /etc/resourced/cpu.conf
%if %{?swap_module} == ON
%config /etc/resourced/swap.conf
%{_unitdir}/resourced-zram.service
%{_unitdir}/graphical.target.wants/resourced-zram.service
%{_bindir}/resourced-zram.sh
%endif
%if %{?vip_agent_module} == ON
%config /etc/resourced/vip-process.conf
%attr(-,root, root) %{_bindir}/vip-release-agent
%endif
%if %{?timer_slack} == ON
%config /etc/resourced/timer-slack.conf
%endif
%{exclude_list_full_path}
%if %{?powertop_state} == ON
/usr/share/powertop-wrapper/header.html
%endif

#memps
%attr(-,root, root) %{_bindir}/memps

%files -n libresourced
%manifest libresourced.manifest
%defattr(-,root,root,-)
/usr/share/license/libresourced
#proc-stat part
%{_libdir}/libproc-stat.so.*
#network part
%{_libdir}/libresourced.so.*
#powertop-wrapper part
%if %{?powertop_state} == ON
%{_libdir}/libpowertop-wrapper.so.*
%endif

%files -n libresourced-devel
%defattr(-,root,root,-)
%{_libdir}/pkgconfig/*.pc
%{_includedir}/system/resourced.h
#proc-stat part
%{_includedir}/system/proc_stat.h
%{_libdir}/libproc-stat.so
#network part
%if %{?network_state} == ON
%{_includedir}/system/data_usage.h
%endif
%{_libdir}/libresourced.so
#powertop-wrapper part
%if %{?powertop_state} == ON
%{_includedir}/system/powertop-dapi.h
%{_libdir}/libpowertop-wrapper.so
%endif
