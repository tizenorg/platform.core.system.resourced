PROJECT(mem-stress)

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/InstallSymlink.cmake)

ADD_EXECUTABLE(${PROJECT_NAME}
  ${CMAKE_CURRENT_SOURCE_DIR}/mem-stress.c
  )

TARGET_LINK_LIBRARIES(${PROJECT_NAME} resourced_shared)

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/mem-stress.service
  DESTINATION lib/systemd/system)

INSTALL_SYMLINK(../mem-stress.service lib/systemd/system/graphical.target.wants/mem-stress.service)
