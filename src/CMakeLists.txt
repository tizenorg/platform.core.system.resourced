CMAKE_MINIMUM_REQUIRED (VERSION 2.6)

#CMake doesnt' support same project name for several TARGETS
# libresourced uses it
PROJECT(resource_d)

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/InstallSymlink.cmake)
INCLUDE(${CMAKE_SOURCE_DIR}/cmake/ProcessGPERF.cmake)

PROCESS_GPERF(${COMMON_SOURCE_DIR}/smaps-lookup.gperf ${COMMON_SOURCE_DIR}/smaps-lookup.c)
PROCESS_GPERF(${COMMON_SOURCE_DIR}/meminfo-lookup.gperf ${COMMON_SOURCE_DIR}/meminfo-lookup.c)
SET(RESOURCED_SHARED_SOURCES ${RESOURCED_SHARED_SOURCES}
  ${COMMON_SOURCE_DIR}/smaps-lookup.c
  ${COMMON_SOURCE_DIR}/meminfo-lookup.c
  )

SET(CMAKE_EXTRA_INCLUDE_FILES unistd.h)

INCLUDE_DIRECTORIES(${RESOURCED_INCLUDEDIR}
  ${RESOURCED_SOURCE_DIR}
  ${HEART_SOURCE_DIR}/include
  ${MEMORY_SOURCE_DIR}
  ${PROC-STAT_SOURCE_DIR}/include
  ${APP-STAT_SOURCE_DIR}/include
  ${NETWORK_SOURCE_DIR}/include
  ${BLOCK_SOURCE_DIR}/include
  ${RESOURCED_DBUS_SOURCE_DIR}/include
  ${FREEZER_SOURCE_DIR}/include
)

SET(SOURCES
  ${PROC-STAT_SOURCE_DIR}/proc-handler.c
  ${PROC-STAT_SOURCE_DIR}/proc-main.c
  ${PROC-STAT_SOURCE_DIR}/proc-noti.c
  ${PROC-STAT_SOURCE_DIR}/proc-process.c
  ${PROC-STAT_SOURCE_DIR}/proc-monitor.c
  ${PROC-STAT_SOURCE_DIR}/proc-usage-stats.c
  ${PROC-STAT_SOURCE_DIR}/proc-usage-stats-helper.c
  ${PROC-STAT_SOURCE_DIR}/proc-appusage.c
  ${PROC-STAT_SOURCE_DIR}/proc-info.c
  ${SLUGGISH_SOURCE_DIR}/sluggish.c
  ${RESOURCED_SOURCE_DIR}/init.c
  ${RESOURCED_SOURCE_DIR}/main.c
  ${COMMON_SOURCE_DIR}/procfs.c
  )
IF("${DEBUG_LOG}" STREQUAL "ON")
  ADD_DEFINITIONS("-DPROC_DEBUG")
ENDIF()

INSTALL(FILES ${DATA_DIR}/${EXCLUDE_LIST_FILE_NAME} DESTINATION /usr/etc)
#network module
IF("${NETWORK_MODULE}" STREQUAL "ON")
  SET(SOURCES ${SOURCES}
    ${NETWORK_SOURCE_DIR}/counter.c
    )
  IF("${DATAUSAGE_TYPE}" STREQUAL "NFACCT")
    SET(CONFIG_DATAUSAGE_NFACCT 1)
    SET(SOURCES ${SOURCES}
      ${NETWORK_SOURCE_DIR}/nfacct-rule.c
      ${NETWORK_SOURCE_DIR}/nf-restriction.c
      )
  ELSE()
    SET(SOURCES ${SOURCES}
      ${NETWORK_SOURCE_DIR}/generic-netlink.c
      ${NETWORK_SOURCE_DIR}/ktgrabber-restriction.c
      ${NETWORK_SOURCE_DIR}/ktgrabber-parser.c
      )
  ENDIF()

  IF("${WEARABLE_NOTI}" STREQUAL "ON")
    SET(SOURCES ${SOURCES}
      ${NETWORK_SOURCE_DIR}/notification-wearable.c
      )
  ELSE()
    SET(SOURCES ${SOURCES}
      ${NETWORK_SOURCE_DIR}/notification-mobile.c
      )
  ENDIF()

  SET(SOURCES ${SOURCES}
    ${NETWORK_SOURCE_DIR}/counter-process.c
    ${NETWORK_SOURCE_DIR}/options-private.c
    ${NETWORK_SOURCE_DIR}/datausage-quota-processing.c
    ${NETWORK_SOURCE_DIR}/datausage-vconf-callbacks.c
    ${NETWORK_SOURCE_DIR}/datausage-vconf-common.c
    ${NETWORK_SOURCE_DIR}/specific-trace.c
    ${NETWORK_SOURCE_DIR}/datausage-common.c
    ${NETWORK_SOURCE_DIR}/iface-cb.c
    ${NETWORK_SOURCE_DIR}/nl-helper.c
    ${NETWORK_SOURCE_DIR}/restriction-handler.c
    ${NETWORK_SOURCE_DIR}/restriction-helper.c
    ${NETWORK_SOURCE_DIR}/restriction-local.c
    ${NETWORK_SOURCE_DIR}/tethering-restriction.c
    ${NETWORK_SOURCE_DIR}/db-guard.c
    )

  INSTALL(FILES ${NETWORK_SOURCE_DIR}/network.conf
    DESTINATION /etc/resourced)
  INSTALL(FILES ${NETWORK_SOURCE_DIR}/500.resourced-datausage.patch.sh
    DESTINATION /etc/opt/upgrade)

  SET(REQUIRES_LIST ${REQUIRES_LIST}
    openssl
    tapi
    )


ENDIF()


#freezer module
IF("${FREEZER_MODULE}" STREQUAL "ON")
   SET(SOURCES ${SOURCES} ${FREEZER_SOURCE_DIR}/freezer.c)
   ADD_DEFINITIONS("-DSYSTEM_LIB_PATH=\"${LIB_INSTALL_DIR}\"")
ELSE()
   SET(SOURCES ${SOURCES} ${FREEZER_SOURCE_DIR}/freezer-common.c)
ENDIF()

#resourced DBus module
#SET(SOURCES ${SOURCES}
#  ${RESOURCED_DBUS_SOURCE_DIR}/resourced-dbus.c
#  )

IF("${VIP_AGENT}" STREQUAL "ON")
  SET(SOURCES ${SOURCES}
    ${VIP_SOURCE_DIR}/vip-process.c
    )
ENDIF()

#heart module
IF("${HEART_MODULE}" STREQUAL "ON")
  SET(SOURCES ${SOURCES}
    ${HEART_SOURCE_DIR}/logging.c
    ${HEART_SOURCE_DIR}/heart.c
    ${HEART_SOURCE_DIR}/heart-abnormal.c
    ${HEART_SOURCE_DIR}/heart-appopt.c
    ${HEART_SOURCE_DIR}/heart-cpu.c
    ${HEART_SOURCE_DIR}/heart-memory.c
    ${HEART_SOURCE_DIR}/heart-battery.c
    ${HEART_SOURCE_DIR}/heart-storage.c
    ${HEART_SOURCE_DIR}/decision.c
    ${HEART_SOURCE_DIR}/decision-memory.c
    )
  ADD_DEFINITIONS("-DHEART_SUPPORT")
  IF("${DEBUG_LOG}" STREQUAL "ON")
    ADD_DEFINITIONS("-DLOGGING_DEBUG")
  ENDIF()
ENDIF()

#memory module
IF("${MEMORY_MODULE}" STREQUAL "ON")
  SET(SOURCES ${SOURCES}
    ${MEMORY_SOURCE_DIR}/lowmem-dbus.c
    ${MEMORY_SOURCE_DIR}/memcontrol.c
    ${MEMORY_SOURCE_DIR}/vmpressure-lowmem-handler.c
    )
  ADD_DEFINITIONS("-DMEMORY_SUPPORT")
ENDIF()

#swap module
IF("${SWAP_MODULE}" STREQUAL "ON")
  SET(SOURCES ${SOURCES}
    ${SWAP_SOURCE_DIR}/swap.c
    )
  ADD_DEFINITIONS("-DSWAP_SUPPORT")
ENDIF()
SET(SOURCES ${SOURCES} ${SWAP_SOURCE_DIR}/swap-common.c)

IF("${CPU_MODULE}" STREQUAL "ON")
  SET(SOURCES ${SOURCES}
    ${CPU_SOURCE_DIR}/cpu.c
    )
ENDIF()

IF("${TIMER_SLACK}" STREQUAL "ON")
  SET(SOURCES ${SOURCES}
    ${TIMER_SOURCE_DIR}/timer-slack.c
    )
ENDIF()

IF("${BLOCK_MODULE}" STREQUAL "ON")
  SET(SOURCES ${SOURCES}
    ${BLOCK_SOURCE_DIR}/block.c
    ${BLOCK_SOURCE_DIR}/block-monitor.c
    )
ENDIF()

SET(REQUIRES_LIST ${REQUIRES_LIST}
	ecore
	dlog
	glib-2.0
	sqlite3
	vconf
	vconf-internal-keys
	ecore-file
	eina
	edbus
	eina
	libsystemd
	leveldb
	eventsystem
  )

INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(RESOURCED_REQUIRE_PKGS REQUIRED ${REQUIRES_LIST})

FOREACH(flag ${RESOURCED_REQUIRE_PKGS_CFLAGS})
  SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -pthread -fPIE -fPIC")

CONFIGURE_FILE(${INCLUDE_COMMON_DIR}/config.h.in
  ${INCLUDE_COMMON_DIR}/config.h)

# resourced shared static lib
FILE(GLOB FILES "${INCLUDE_COMMON_DIR}/*.h")
FOREACH(FILE ${FILES})
  SET(RESOURCED_INCLUDE_HEADERS ${RESOURCED_INCLUDE_HEADERS} ${FILE})
ENDFOREACH()

SET(RESOURCED_INCLUDE_HEADERS ${RESOURCED_INCLUDE_HEADERS}
  ${NETWORK_SOURCE_DIR}/include/datausage-vconf-callbacks.h
  ${NETWORK_SOURCE_DIR}/include/iface-cb.h
  )

FILE(GLOB FILES "${COMMON_SOURCE_DIR}/*.c")
FOREACH(FILE ${FILES})
  SET(RESOURCED_SHARED_SOURCES ${RESOURCED_SHARED_SOURCES} ${FILE})
ENDFOREACH()

FILE(GLOB FILES "${COMMON_SOURCE_DIR}/*.h")
FOREACH(FILE ${FILES})
  SET(RESOURCED_SHARED_HEADERS ${RESOURCED_SHARED_HEADERS} ${FILE})
ENDFOREACH()

ADD_LIBRARY(resourced_shared STATIC
  ${RESOURCED_INCLUDE_HEADERS}
  ${RESOURCED_SHARED_SOURCES}
  ${RESOURCED_SHARED_HEADERS}
  )
TARGET_LINK_LIBRARIES(resourced_shared ${RESOURCED_REQUIRE_PKGS_LDFLAGS})

ADD_EXECUTABLE(${PROJECT_NAME} ${SOURCES})
TARGET_LINK_LIBRARIES(${PROJECT_NAME}
  resourced_shared ${RESOURCED_REQUIRE_PKGS_LDFLAGS} "-pie -lrt -lm -ldl"
  )

INSTALL(FILES
  ${RESOURCED_SOURCE_DIR}/${RESOURCED}.socket
  ${RESOURCED_SOURCE_DIR}/${RESOURCED}.service
  DESTINATION lib/systemd/system)
INSTALL_SYMLINK(../${RESOURCED}.socket lib/systemd/system/sockets.target.wants/${RESOURCED}.socket)
INSTALL_SYMLINK(../${RESOURCED}.service lib/systemd/system/multi-user.target.wants/${RESOURCED}.service)

IF("${NETWORK_MODULE}" STREQUAL "ON")
  TARGET_LINK_LIBRARIES(${PROJECT_NAME}
    resourced
    app-stat
    storage
    settings
    net-cls
    telephony
    net-iface
    )

  IF("${CMAKE_BUILD_TYPE}" STREQUAL  "DEBUG")
    ADD_EXECUTABLE(test-udp-server ${UTILS_SOURCE_DIR}/udp-server.c ${UTILS_SOURCE_DIR}/udp-common.c)
    ADD_EXECUTABLE(test-udp-client ${UTILS_SOURCE_DIR}/udp-client.c ${UTILS_SOURCE_DIR}/udp-common.c)
    ADD_EXECUTABLE(iface-test ${UTILS_SOURCE_DIR}/iface-test.c)
    TARGET_LINK_LIBRARIES(iface-test net-iface ${RESOURCED_REQUIRE_PKGS_LDFLAGS})
  ENDIF()

  INSTALL(FILES ${DATA_DIR}/traffic_db.sql
    DESTINATION /usr/share)
  INSTALL(FILES ${DATA_DIR}/exception_db.sql
    DESTINATION /usr/share)
ENDIF()

INSTALL(FILES ${INCLUDE_PUBLIC_DIR}/resourced.h DESTINATION include/system)

SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES SKIP_BUILD_RPATH true)
INSTALL(FILES ${PROJECT_NAME}
  DESTINATION ${MAKE_INSTALL_PREFIX}/usr/bin RENAME resourced
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE WORLD_EXECUTE)

IF("${MEMORY_ENG}" STREQUAL "ON")
  INSTALL(FILES ${MEMORY_SOURCE_DIR}/memory_eng.conf
    DESTINATION /etc/resourced RENAME memory.conf)
ELSE()
  INSTALL(FILES ${MEMORY_SOURCE_DIR}/memory_user.conf
    DESTINATION /etc/resourced RENAME memory.conf)
ENDIF()

IF("${SWAP_MODULE}" STREQUAL "ON")
  INSTALL(FILES ${SWAP_SOURCE_DIR}/swap.conf DESTINATION /etc/resourced)
ENDIF()

IF("${HEART_MODULE}" STREQUAL "ON")
  INSTALL(FILES ${HEART_SOURCE_DIR}/heart.conf
    DESTINATION /etc/resourced RENAME heart.conf)
  INSTALL(FILES ${HEART_SOURCE_DIR}/dump_heart_data.sh
    DESTINATION /opt/etc/dump.d/module.d)
ENDIF()

IF("${CPU_MODULE}" STREQUAL "ON")
  INSTALL(FILES ${CPU_SOURCE_DIR}/cpu.conf
    DESTINATION /etc/resourced RENAME cpu.conf)
ELSE()
  INSTALL(PROGRAMS ${CMAKE_BINARY_DIR}/scripts/resourced-cpucgroup.sh DESTINATION bin)
ENDIF()

IF("${TIMER_SLACK}" STREQUAL "ON")
  INSTALL(FILES ${TIMER_SOURCE_DIR}/timer-slack.conf
    DESTINATION /etc/resourced RENAME timer-slack.conf)
ENDIF()

IF("${VIP_AGENT}" STREQUAL "ON")
  ADD_EXECUTABLE(vip-release-agent ${VIP_SOURCE_DIR}/vip-release-agent.c)
  TARGET_LINK_LIBRARIES(vip-release-agent resourced_shared dlog)
  INSTALL(TARGETS vip-release-agent DESTINATION bin)
  INSTALL(FILES ${VIP_SOURCE_DIR}/vip-process.conf
    DESTINATION
    /etc/resourced RENAME vip-process.conf)
ENDIF()

IF("${BLOCK_MODULE}" STREQUAL "ON")
  INSTALL(FILES ${BLOCK_SOURCE_DIR}/block.conf
    DESTINATION /etc/resourced RENAME block.conf)
ENDIF()

IF("${FREEZER_MODULE}" STREQUAL "ON")
  INSTALL(FILES ${FREEZER_SOURCE_DIR}/freezer.conf
    DESTINATION /etc/resourced RENAME freezer.conf)
  INSTALL(FILES ${FREEZER_SOURCE_DIR}/libsystem-freezer.so.${ARCH} DESTINATION ${LIB_INSTALL_DIR}
    RENAME libsystem-freezer.so)
ENDIF()

INSTALL(FILES ${PROC-STAT_SOURCE_DIR}/proc.conf
  DESTINATION /etc/resourced RENAME proc.conf)

ADD_EXECUTABLE(hashtest ${UTILS_SOURCE_DIR}/hashtest.c)
TARGET_LINK_LIBRARIES(hashtest ${RESOURCED_REQUIRE_PKGS_LDFLAGS})

IF("${MEM_STRESS}" STREQUAL "ON")
	ADD_SUBDIRECTORY(mem-stress)
ENDIF()
ADD_SUBDIRECTORY(${PROC-STAT_SOURCE_DIR})
ADD_SUBDIRECTORY(${NETWORK_SOURCE_DIR})
IF("${TESTS_MODULE}" STREQUAL "ON")
  ADD_SUBDIRECTORY(${TESTS_SOURCE_DIR})
ENDIF()

