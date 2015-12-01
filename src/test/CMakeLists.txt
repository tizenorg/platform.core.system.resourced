CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(resourced-test C)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/src)

SET(SRCS
	test.c
	main.c
)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED edbus dlog glib-2.0)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

IF("${SLP_TESTS}" STREQUAL "ON")
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -g -fno-omit-frame-pointer -finstrument-functions")
ELSE()
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -g -fno-omit-frame-pointer")
ENDIF()

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -fPIE")
MESSAGE("FLAGS: ${CMAKE_C_FLAGS}")
SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--as-needed -pie")
MESSAGE("FLAGS: ${CMAKE_EXE_LINKER_FLAGS}")

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")
ADD_DEFINITIONS("-DENABLE_TEST_DLOG")

ADD_EXECUTABLE(${PROJECT_NAME} ${SRCS})
TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${pkgs_LDFLAGS})

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)

# test smaps
ADD_EXECUTABLE(test-smaps ${TEST_DIR}/test-smaps.c)
TARGET_LINK_LIBRARIES(test-smaps resourced_shared)
INSTALL(TARGETS test-smaps DESTINATION lib/resourced/test)

# test procfs
ADD_EXECUTABLE(test-procfs ${TEST_DIR}/test-procfs.c)
TARGET_LINK_LIBRARIES(test-procfs resourced_shared)
INSTALL(TARGETS test-procfs DESTINATION lib/resourced/test)

# test file-helper
ADD_EXECUTABLE(test-file-helper ${TEST_DIR}/test-file-helper.c)
TARGET_LINK_LIBRARIES(test-file-helper
  resourced_shared ${RESOURCED_REQUIRE_PKGS_LDFLAGS})
INSTALL(TARGETS test-file-helper DESTINATION lib/resourced/test)

# test autolaunch utility
ADD_EXECUTABLE(sluggish-test ${TEST_DIR}/sluggish-test.c)
TARGET_LINK_LIBRARIES(sluggish-test resourced_shared)
INSTALL(TARGETS sluggish-test DESTINATION bin)
INSTALL(FILES ${TEST_DIR}/sluggish-test.conf DESTINATION /etc/resourced)

ADD_SUBDIRECTORY(activation)
