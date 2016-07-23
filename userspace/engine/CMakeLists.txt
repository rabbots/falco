include_directories("${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp")
include_directories("${LUAJIT_INCLUDE}")

include_directories("${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap")
include_directories("${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp")
include_directories("${PROJECT_BINARY_DIR}/userspace/engine")
include_directories("${CURL_INCLUDE_DIR}")
include_directories("${YAMLCPP_INCLUDE_DIR}")
include_directories("${LUAJIT_INCLUDE}")
include_directories("${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include")

add_definitions(-DK8S_DISABLE_THREAD)

add_library(falco_engine STATIC rules.cpp falco_common.cpp falco_engine.cpp)
add_library(falco_engine_objs OBJECT rules.cpp falco_common.cpp falco_engine.cpp)

set(FALCO_ENGINE_LIBRARIES
	"${LPEG_SRC}/lpeg.a"
	"${LYAML_LIB}"
        "${LIBYAML_LIB}"
	PARENT_SCOPE)

target_link_libraries(falco_engine
  ${FALCO_ENGINE_LIBRARIES})

configure_file(config_falco_engine.h.in config_falco_engine.h)

install(DIRECTORY lua
	DESTINATION share/falco
	FILES_MATCHING PATTERN *.lua)
