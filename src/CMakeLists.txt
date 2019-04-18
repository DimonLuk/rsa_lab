set(LANG_LOCAL $ENV{LANG_LOCAL})
if($ENV{MODE} STREQUAL "static")
  set(LOAD_AS 1)
elseif($ENV{MODE} STREQUAL "shared")
  set(LOAD_AS $ENV{LOAD_AS})
endif()

configure_file(${PROJECT_SOURCE_DIR}/src/include/src_config.h.in ${PROJECT_SOURCE_DIR}/src/include/src_config.h)

add_executable(os_rsa_lab main.c)
target_link_libraries(os_rsa_lab rsa)
