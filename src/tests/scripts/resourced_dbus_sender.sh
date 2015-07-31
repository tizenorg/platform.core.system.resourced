#!/bin/bash

usage() {
	echo "resourced_dbus_sender [method_call/signal_name] [method options]"
	if [ "$1" == "default" ]
		then
		echo "	Supported Method calls:"
		echo "		Memory_Usage <smack enable/disable> <array of pid>: Call to the Proc_Method_Usage method of proc-usage-stats-api"
		echo "		CPU_Usage <smack enable/disable> <array of pid>: Call to the Proc_CPU_Usage method of proc-usage-stats-api"
		echo "		AUL_Launch <pid> <app name> <pkg type>: Call to the AppLaunch signal of org.tizen.aul.AppStatus"
		echo "		Prelaunch_OOM [appid] [pkgid]: Call to the prelaunch handler in resourced"
		echo "		OOM_Trigger: Sends signal to the oom trigger dbus handler in resourced"
		echo "		Help <Method_Call>: Details about that method call"
	fi
	if [ "$1" == "Memory_Usage" ]
		then
		echo "		Memory_Usage <smack enable/disable> <array of pid>: Call to the Proc_Method_Usage method of proc-usage-stats-api"
	fi
	if [ "$1" == "CPU_Usage" ]
		then
		echo "		CPU_Usage <smack enable/disable> <array of pid>: Call to the Proc_CPU_Usage method of proc-usage-stats-api"
	fi
	if [ "$1" == "AUL_Launch" ]
		then
		echo "		AUL_Launch <pid> <app name> <pkg type>: Call to the AppLaunch signal of org.tizen.aul.AppStatus"
		echo "			pkg type: svc, ui, widget, watch"
	fi
	if [ "$1" == "Prelaunch_OOM" ]
		then
		echo "		Prelaunch_OOM [appid] [pkgid]: Call to the prelaunch handler in resourced"
		echo "			If there are not arguments after Prelaunch_OOM:"
		echo "				sends default appid and pkgid"
		echo "			Else:"
		echo "				set: sends input appid and pkgid; need 2nd and 3rd argument to script"
	fi
	if [ "$1" == "OOM_Trigger" ]
		then
		echo "		OOM_Trigger: Sends signal to the oom trigger dbus handler in resourced"
	fi
	exit -1
}

if [ $# -lt 1 ]
	then
	usage default
fi

method=$1

case "$method" in
	Memory_Usage )
		if [ $# -lt 3 ]
			then
			usage Memory_Usage
		fi
		smack_label=$2
		arr=$3
		if [ "$smack_label" == "enable" ]
			then
			echo "Smack labeling enabled"
			echo "resourced:systeminfo" > /proc/self/attr/current
		fi
		dbus-send --system --type=method_call --print-reply --reply-timeout=120000 --dest=org.tizen.resourced /Org/Tizen/ResourceD/Process org.tizen.resourced.process.ProcMemoryUsage array:int32:$arr
		;;
	CPU_Usage )
		if [ $# -lt 3 ]
			then
			usage CPU_Usage
		fi
		smack_label=$2
		arr=$3
		if [ "$smack_label" == "enable" ]
			then
			echo "Smack labeling enabled"
			echo "resourced:systeminfo" > /proc/self/attr/current
		fi
		dbus-send --system --type=method_call --print-reply --reply-timeout=120000 --dest=org.tizen.resourced /Org/Tizen/ResourceD/Process org.tizen.resourced.process.ProcCpuUsage array:int32:$arr
		;;
	AUL_Launch )
		if [ $# -lt 4 ]
			then
			usage AUL_Launch
		fi
		pid=$2
		appid=$3
		pkgtype=$4
		dbus-send --system --dest=org.tizen.aul.AppStatus /Org/Tizen/Aul/AppStatus org.tizen.aul.AppStatus.AppLaunch int32:$pid string:'$appid' string:'$pkgtype'
		;;
	Prelaunch_OOM )
		if [ $# -lt 2 ]
			then
			appid="org.prelaunch"
			pkgid="org.pkg_prelaunch"
		else
			if [ $# -lt 3 ]
				then
				usage Prelaunch_OOM
			else
				appid=$2
				pkgid=$3
			fi
		fi
		flags=1		#Set only PROC_LARGEMEMORY flag
		dbus-send --system --dest=org.tizen.resourced /Org/Tizen/ResourceD/Process org.tizen.resourced.process.ProcPrelaunch string:$appid string:$pkgid int32:$flags
		;;
	OOM_Trigger )
		dbus-send --system --dest=org.tizen.resourced /Org/Tizen/ResourceD/Oom org.tizen.resourced.oom.Trigger
		;;
	Help )
		if [ $# -lt 2 ]
			then
			usage default
		fi
		usage $2
		;;
	*)
		usage default
esac
