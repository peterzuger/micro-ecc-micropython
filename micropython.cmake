add_library(usermod_micro_ecc INTERFACE)

target_sources(usermod_micro_ecc INTERFACE
  ${CMAKE_CURRENT_LIST_DIR}/micro_ecc.c
)

string(FIND "${MICROPY_CPP_FLAGS_EXTRA}" "-DMODULE_MICRO_ECC_ENABLED=1" matchres)

if(${matchres} GREATER_EQUAL 0)
  target_sources(usermod_micro_ecc INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/micro-ecc/uECC.c
  )
endif()

target_include_directories(usermod_micro_ecc INTERFACE
  ${CMAKE_CURRENT_LIST_DIR}/micro-ecc/
)

target_link_libraries(usermod INTERFACE usermod_micro_ecc)
