include(ExternalProject)


ExternalProject_Add(frida-gum-prebuilt
	URL https://github.com/frida/frida/releases/download/15.1.28/frida-gum-devkit-15.1.28-linux-x86_64.tar.xz
    CONFIGURE_COMMAND ""
	BUILD_COMMAND ""
	INSTALL_COMMAND ""
	UPDATE_COMMAND ""
)
ExternalProject_Get_property(frida-gum-prebuilt SOURCE_DIR)

add_library(frida-gum STATIC IMPORTED GLOBAL)
set_target_properties(frida-gum PROPERTIES IMPORTED_LOCATION ${SOURCE_DIR}/libfrida-gum.a)

