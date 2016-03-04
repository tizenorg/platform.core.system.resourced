CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

SET(fw_name "resourced")
SET(RESOURCED resourced)
SET(LIBS libs)
SET(PROC-STAT proc-stat)
SET(NETWORK rd-network)

PROJECT(${fw_name})

#Set CFLAGS
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE -DRESOURCED_BUILD -Wall -Werror -fvisibility=hidden")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GNU_SOURCE -DRESOURCED_BUILD -Wall -Werror -fvisibility=hidden")

#Set as-needed
SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--as-needed")
SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--as-needed")

#Set debug-mode if needed
IF("${CMAKE_BUILD_TYPE}" STREQUAL  "DEBUG")
  STRING(REGEX REPLACE "-O2" "" CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
  STRING(REGEX REPLACE "-D_FORTIFY_SOURCE=2" "" CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
  ADD_DEFINITIONS(-DNETWORK_DEBUG_ENABLED)
  SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -O0 -g")
  SET(CMAKE_VERBOSE_MAKEFILE ON)
  SET(VERBOSE 1)
ELSE()
#set compile size optimization option in case of none DEBUG
  SET(ADDITIONAL_OFLAGS "-fdata-sections -ffunction-sections -Wl,--gc-sections -fno-exceptions")
  SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${ADDITIONAL_OFLAGS}")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${ADDITIONAL_OFLAGS}")
ENDIF()

SET(PREFIX ${CMAKE_INSTALL_PREFIX})

#following section is needed for pkg-config *.in file
SET(INCLUDEDIR ${PREFIX}/include)
SET(PC_NAME lib${RESOURCED})
SET(PC_REQUIRED "glib-2.0 vconf vconf-internal-keys sqlite3 dlog eina edbus")
SET(PC_PROVIDED_LIBS "-l${PROC-STAT} -l${RESOURCED}")

SET(PC_CFLAGS -I\${includedir}/system)
SET(VERSION ${FULLVER})

CONFIGURE_FILE(
    lib${RESOURCED}.pc.in
    ${CMAKE_SOURCE_DIR}/lib${RESOURCED}.pc
    @ONLY
)

#init variables with sources
SET(DATA_DIR                    ${CMAKE_SOURCE_DIR}/data)
SET(CMAKELISTS_DIR              ${CMAKE_SOURCE_DIR}/CMakeLists)
SET(INCLUDE_COMMON_DIR          ${CMAKE_SOURCE_DIR}/src/common)
SET(INCLUDE_MEMORY_DIR          ${CMAKE_SOURCE_DIR}/src/memory)
SET(INCLUDE_PUBLIC_DIR          ${CMAKE_SOURCE_DIR}/include)
SET(RESOURCED_INCLUDEDIR        ${INCLUDE_COMMON_DIR} ${INCLUDE_PUBLIC_DIR})

SET(SOURCE_DIR                  ${CMAKE_SOURCE_DIR}/src)
SET(TEST_DIR                    ${SOURCE_DIR}/test)
SET(UTILS_SOURCE_DIR            ${SOURCE_DIR}/utils)
SET(RESOURCED_SOURCE_DIR        ${SOURCE_DIR}/resourced)
SET(PROC-STAT_SOURCE_DIR        ${SOURCE_DIR}/proc-stat)
SET(SLUGGISH_SOURCE_DIR         ${SOURCE_DIR}/sluggish)
SET(MEMORY_SOURCE_DIR           ${SOURCE_DIR}/memory)
SET(SWAP_SOURCE_DIR             ${SOURCE_DIR}/swap)
SET(MODULES_SOURCE_DIR          ${SOURCE_DIR}/modules)
SET(FREEZER_SOURCE_DIR          ${SOURCE_DIR}/freezer)
SET(HEART_SOURCE_DIR            ${SOURCE_DIR}/heart)
SET(NETWORK_SOURCE_DIR          ${SOURCE_DIR}/network)
SET(COMMON_SOURCE_DIR           ${SOURCE_DIR}/common)
SET(CPU_SOURCE_DIR              ${SOURCE_DIR}/cpu)
SET(VIP_SOURCE_DIR              ${SOURCE_DIR}/vip-agent)
SET(TIMER_SOURCE_DIR            ${SOURCE_DIR}/timer-slack)
SET(BLOCK_SOURCE_DIR            ${SOURCE_DIR}/block)
SET(RESOURCED_DBUS_SOURCE_DIR   ${SOURCE_DIR}/resourced-dbus)
SET(TESTS_SOURCE_DIR		${SOURCE_DIR}/tests)

INSTALL(FILES ${CMAKE_SOURCE_DIR}/lib${RESOURCED}.pc DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/resourced.conf DESTINATION /etc/dbus-1/system.d)

ADD_SUBDIRECTORY(src)
