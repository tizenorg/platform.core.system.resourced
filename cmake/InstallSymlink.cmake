MACRO(INSTALL_SYMLINK _filepath _sympath)
  GET_FILENAME_COMPONENT(_symname ${_sympath} NAME)
  GET_FILENAME_COMPONENT(_installdir ${_sympath} PATH)

  EXECUTE_PROCESS(COMMAND "${CMAKE_COMMAND}" -E create_symlink
    ${_filepath}
    ${CMAKE_CURRENT_BINARY_DIR}/${_symname})
  INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/${_symname}
    DESTINATION ${_installdir})
ENDMACRO(INSTALL_SYMLINK)
