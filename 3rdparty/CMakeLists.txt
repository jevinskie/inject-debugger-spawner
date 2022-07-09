include(FetchContent)
FetchContent_Declare(
    frida-gum-prebuilt
    URL https://github.com/frida/frida/releases/download/15.1.28/frida-gum-devkit-15.1.28-linux-x86_64.tar.xz
    FETCHCONTENT_TRY_FIND_PACKAGE_MODE NEVER
)
FetchContent_MakeAvailable(frida-gum-prebuilt)
FetchContent_GetProperties(frida-gum-prebuilt SOURCE_DIR FRIDA_GUM_SRC_DIR)

add_library(frida-gum STATIC IMPORTED GLOBAL)
set_target_properties(frida-gum PROPERTIES IMPORTED_LOCATION ${FRIDA_GUM_SRC_DIR}/libfrida-gum.a)
target_include_directories(frida-gum INTERFACE ${FRIDA_GUM_SRC_DIR})

set(BUILD_TESTING OFF)
add_subdirectory(cpp-subprocess)

add_subdirectory(magic_enum)
