add_library(debugbreak INTERFACE IMPORTED GLOBAL)
target_include_directories(debugbreak INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/debugbreak)

set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
set(BUILD_TESTING OFF)
add_subdirectory(cpp-subprocess)

add_subdirectory(magic_enum)
