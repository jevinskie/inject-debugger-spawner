add_library(injdbgspawn SHARED injdbgspawn.cpp)
target_link_libraries(injdbgspawn PRIVATE frida-gum)
add_dependencies(injdbgspawn frida-gum-prebuilt)
