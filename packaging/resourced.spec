Name:       resourced
Summary:    Resource management daemon
Version:    0.2.87
Release:    0
Group:      System/Libraries
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source2:    resourced-cpucgroup.service

# Default setting
%define block_module		ON
%define cpu_module			ON
%define freezer_module		OFF
%define heart_module		ON
%define memory_module		ON
%define mem_stress			OFF
%define swap_module			OFF
%define timer_slack			OFF
%define vip_agent_module	ON

%define memory_eng			ON
%define wearable_noti		OFF
%define debug_log			OFF

# Module switch for each profile
# Define only difference with default setting
%if "%{?profile}" == "mobile"
	%define freezer_module ON
%endif

%if "%{?profile}" == "wearable"
	%define wearable_noti ON
%endif

%if "%{?profile}" == "tv"
	%define heart_module OFF
	%define vip_agent_module OFF
%endif

%ifarch aarch64
	%define heart_module OFF
%endif


%define exclude_list_file_name resourced_proc_exclude.ini
%define exclude_list_full_path %{TZ_SYS_ETC}/%{exclude_list_file_name}
%define exclude_list_opt_full_path %{TZ_SYS_ETC}/%{exclude_list_file_name}
%define database_full_path %{TZ_SYS_GLOBALUSER_DB}/.resourced-datausage.db

%define logging_storage_db_full_path %{TZ_SYS_GLOBALUSER_DB}/.resourced-heart-storage.db

%define rd_config_path /etc/resourced

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
BuildRequires:  pkgconfig(libsystemd)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(leveldb)
BuildRequires:  pkgconfig(eventsystem)
BuildRequires:  pkgconfig(capi-system-info)
BuildRequires:  pkgconfig(libtzplatform-config)
BuildRequires:  pkgconfig(storage)

#only for data types
BuildRequires:  pkgconfig(tapi)

Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

BuildRequires:  gperf

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

export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"

%ifarch %{arm}
	%define ARCH armv7l
%else
	%ifarch aarch64
		%define ARCH arm64
	%else
		%ifarch %ix86
			%define ARCH i586
		%else
			%define ARCH x86_64
		%endif
	%endif
%endif

%cmake . -DFULLVER=%{version} \
	 -DMAJORVER=${MAJORVER} \
	 -DARCH=%{ARCH} \
	 -DCMAKE_BUILD_TYPE=Release \
	 -DEXCLUDE_LIST_FILE_NAME=%{exclude_list_file_name} \
	 -DEXCLUDE_LIST_FULL_PATH=%{exclude_list_full_path} \
	 -DDATABASE_FULL_PATH=%{database_full_path} \
	 -DEXCLUDE_LIST_OPT_FULL_PATH=%{exclude_list_opt_full_path} \
	 -DBLOCK_MODULE=%{block_module} \
	 -DCPU_MODULE=%{cpu_module} \
	 -DFREEZER_MODULE=%{freezer_module} \
	 -DHEART_MODULE=%{heart_module} \
	 -DMEMORY_MODULE=%{memory_module} \
	 -DMEM_STRESS=%{mem_stress} \
	 -DSWAP_MODULE=%{swap_module} \
	 -DTIMER_SLACK=%{timer_slack} \
	 -DVIP_AGENT=%{vip_agent_module} \
	 -DMEMORY_ENG=%{memory_eng} \
	 -DWEARABLE_NOTI=%{wearable_noti} \
	 -DDEBUG_LOG=%{debug_log} \
	 -DDATAUSAGE_TYPE=NFACCT \
	 -DRD_SYS_HOME=%{TZ_SYS_HOME} \
	 -DRD_SYS_ETC=%{TZ_SYS_ETC} \
	 -DRD_SYS_STORAGE=%{TZ_SYS_STORAGE} \
	 -DRD_SYS_DATA=%{TZ_SYS_GLOBALUSER_DATA} \
	 -DRD_SYS_DB=%{TZ_SYS_GLOBALUSER_DB} \
	 -DRD_SYS_SHARE=%{TZ_SYS_SHARE} \
	 -DRD_SYS_VAR=%{TZ_SYS_VAR} \
	 -DRD_USER_CONTENT=%{TZ_USER_CONTENT} \
	 -DRD_CONFIG_PATH=%{rd_config_path}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp -f LICENSE %{buildroot}/usr/share/license/%{name}
cp -f LICENSE %{buildroot}/usr/share/license/libresourced

%make_install
%if %{?heart_module} == ON
	mkdir -p %{buildroot}/%{TZ_SYS_GLOBALUSER_DATA}/heart
	mkdir -p %{buildroot}/%{TZ_SYS_GLOBALUSER_DB}
	sqlite3 --line %{buildroot}%{logging_storage_db_full_path} 'PRAGMA journal_mode = WAL'
	touch %{buildroot}%{logging_storage_db_full_path}-shm
	touch %{buildroot}%{logging_storage_db_full_path}-wal
%endif

%if %{?cpu_module} == OFF
	%install_service graphical.target.wants resourced-cpucgroup.service
%endif

%pre resourced
if [ "$1" = "2" ]; then # upgrade begins
	systemctl stop resourced.service
fi

%post

/sbin/ldconfig

mkdir -p %{_sysconfdir}/systemd/default-extra-dependencies/ignore-units.d/
ln -sf %{_unitdir}/resourced.service %{_sysconfdir}/systemd/default-extra-dependencies/ignore-units.d/

#install init.d script
mkdir -p %{TZ_SYS_ETC}
#make empty dynamic exclude list for first installation
touch %{exclude_list_opt_full_path}

if [ "$1" = "2" ]; then # upgrade begins
	systemctl start resourced.service
fi

%postun -p /sbin/ldconfig

%files -n resourced
/usr/share/license/%{name}
%attr(-,root, root) %{_bindir}/resourced
%manifest resourced.manifest
%config %{_sysconfdir}/dbus-1/system.d/resourced.conf
%{_unitdir}/resourced.service
%{_unitdir}/multi-user.target.wants/resourced.service
%{_unitdir}/resourced.socket
%{_unitdir}/sockets.target.wants/resourced.socket
%config %{rd_config_path}/memory.conf
%config %{rd_config_path}/proc.conf
%if %{?cpu_module} == ON
	%config %{rd_config_path}/cpu.conf
%else
	%{_bindir}/resourced-cpucgroup.sh
	%{_unitdir}/resourced-cpucgroup.service
	%{_unitdir}/graphical.target.wants/resourced-cpucgroup.service
%endif
%if %{?swap_module} == ON
	%config %{rd_config_path}/swap.conf
%endif
%if %{?vip_agent_module} == ON
	%config %{rd_config_path}/vip-process.conf
	%attr(-,root, root) %{_bindir}/vip-release-agent
%endif
%if %{?timer_slack} == ON
	%config %{rd_config_path}/timer-slack.conf
%endif
%if %{?block_module} == ON
	%config %{rd_config_path}/block.conf
%endif
%if %{?freezer_module} == ON
	%{_libdir}/libsystem-freezer.so*
	%config %{rd_config_path}/freezer.conf
%endif
%{exclude_list_full_path}
%if %{?heart_module} == ON
	%config %{rd_config_path}/heart.conf
	%attr(700, root, root) %{TZ_SYS_ETC}/dump.d/module.d/dump_heart_data.sh
	%attr(644, root, root) %{logging_storage_db_full_path}
	%attr(644, root, root) %{logging_storage_db_full_path}-shm
	%attr(644, root, root) %{logging_storage_db_full_path}-wal
%endif
#mem-stress
%if %{?mem_stress} == ON
%attr(-,root, root) %{_bindir}/mem-stress
%{_unitdir}/mem-stress.service
%{_unitdir}/graphical.target.wants/mem-stress.service
%endif

%files -n libresourced
%manifest libresourced.manifest
%defattr(-,root,root,-)
/usr/share/license/libresourced
#proc-stat part
%{_libdir}/libproc-stat.so.*

%files -n libresourced-devel
%defattr(-,root,root,-)
%{_libdir}/pkgconfig/*.pc
%{_includedir}/system/resourced.h
#proc-stat part
%{_includedir}/system/proc_stat.h
%{_libdir}/libproc-stat.so

