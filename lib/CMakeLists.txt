find_package(fmt CONFIG REQUIRED)

add_library(injdbgspawn SHARED injdbgspawn.cpp)
target_link_libraries(injdbgspawn PRIVATE frida-gum fmt)
