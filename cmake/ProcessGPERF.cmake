MACRO(PROCESS_GPERF _input _output)
  ADD_CUSTOM_COMMAND(
    OUTPUT ${_output}
    COMMAND gperf ${_input} > ${_output}
    DEPENDS ${_input})
ENDMACRO(PROCESS_GPERF)
