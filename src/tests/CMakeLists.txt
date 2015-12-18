SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -Wall -g")

#Dependencies
SET(requires libsystemd)

#Include directories
INCLUDE_DIRECTORIES(
	${TESTS_SOURCE_DIR}/include
	${TESTS_SOURCE_DIR}/memory/include
)

#Setting sources
SET(SRC_TESTS_COMMON 	${TESTS_SOURCE_DIR}/common/fio.c
			${TESTS_SOURCE_DIR}/common/procfs.c)

			
SET(SRC_MEMORY_TEST 	${TESTS_SOURCE_DIR}/memory/resourced_memory_test.c
			${TESTS_SOURCE_DIR}/memory/resourced_memory_test_helper.c
			${SRC_TESTS_COMMON})

SET(SRC_DUMMY_PROCESS 	${TESTS_SOURCE_DIR}/util/resourced_dummy_process.c)
SET(SRC_MEMORY_HOG 	${TESTS_SOURCE_DIR}/util/resourced_hogger_memory.c)
SET(SRC_PROC_STAT_TEST 	${TESTS_SOURCE_DIR}/proc-stat/resourced_proc_stat_test.c)
SET(SRC_DATA_USAGE_TEST	${TESTS_SOURCE_DIR}/network/resourced_data_usage_test.c)

#Linking flags
INCLUDE(FindPkgConfig)
pkg_check_modules(daemon_pkgs REQUIRED ${requires})
FOREACH(flag ${daemon_pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

#Adding executables
ADD_EXECUTABLE (resourced_memory_test ${SRC_MEMORY_TEST})
TARGET_LINK_LIBRARIES(resourced_memory_test ${daemon_pkgs_LDFLAGS})
INSTALL(TARGETS resourced_memory_test DESTINATION bin)

ADD_EXECUTABLE(resourced_proc_stat_test ${SRC_PROC_STAT_TEST})
TARGET_LINK_LIBRARIES(resourced_proc_stat_test ${daemon_pkgs_LDFLAGS} ${PROC-STAT})
INSTALL(TARGETS resourced_proc_stat_test DESTINATION bin)

ADD_EXECUTABLE(resourced_data_usage_test ${SRC_DATA_USAGE_TEST})
TARGET_LINK_LIBRARIES(resourced_data_usage_test ${daemon_pkgs_LDFLAGS} ${RESOURCED})
INSTALL(TARGETS resourced_data_usage_test DESTINATION bin)

ADD_EXECUTABLE(resourced_dummy_process ${SRC_DUMMY_PROCESS})
INSTALL(TARGETS resourced_dummy_process DESTINATION bin)

ADD_EXECUTABLE(resourced_hogger_memory ${SRC_MEMORY_HOG})
INSTALL(TARGETS resourced_hogger_memory DESTINATION bin)

INSTALL(PROGRAMS ${TESTS_SOURCE_DIR}/scripts/resourced_dbus_sender.sh DESTINATION bin)
INSTALL(PROGRAMS ${TESTS_SOURCE_DIR}/scripts/resourced_util_memory_test.sh DESTINATION bin)
