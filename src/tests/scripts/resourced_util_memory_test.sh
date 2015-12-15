#!/bin/bash

MEMCG_ROOT="/sys/fs/cgroup/memory"

function usage() {
	echo "resourced_memory_tests_util [action] [action options]"
	if [ "$1" == "default" ]
		then
		echo "	Supported actions:"
		echo "		Memory_probe: Displays memory usage info and memory cgroup info"
		echo "		Memcg_probe: Displays the cgroup.procs of all the memory subcgroups"
		echo "		MemUsage_probe: Displays memory usage info"
		echo "		Help <Action>: Details about that action"
	fi
	if [ "$1" == "Memory_probe" ]
		then
		echo "		Memory_probe: Displays memory usage info and memory cgroup info"
	fi
	if [ "$1" == "Memcg_probe" ]
		then
		echo "		Memcg_probe: Displays the cgroup.procs of all the memory subcgroups"
	fi
	if [ "$1" == "MemUsage_probe" ]
		then
		echo "		MemUsage_probe: Displays memory usage info"
	fi
	exit -1
}

if [ $# -lt 1 ]
	then
	usage default
fi

function memcg_probe() {
	memcg_names=("foreground" "service" "favorite" "background" "swap")
	echo "Format: pid, oom score adj"
	for memcg in "${memcg_names[@]}"
	do
		echo "$memcg memcg"
		echo "================"
		cat $MEMCG_ROOT/$memcg/cgroup.procs | while read pid
		do
			oom=`cat /proc/$pid/oom_score_adj`
			echo "$pid, $oom"
		done
	done
}

function memusage_probe() {
	memusage_fields=("MemTotal" "MemAvailable")
	for usage_field in "${memusage_fields[@]}"
	do
		cat /proc/meminfo | grep "$usage_field"
	done
}

action=$1

case "$action" in
	Memory_probe )
		echo "Memory probe"
		echo "=================="
		memusage_probe
		echo "-------------------"
		memcg_probe
		;;
	Memcg_probe )
		echo "Memory cgroup probe"
		echo "==================="
		memcg_probe
		;;
	MemUsage_probe )
		echo "Memory usage probe"
		echo "=================="
		memusage_probe
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
