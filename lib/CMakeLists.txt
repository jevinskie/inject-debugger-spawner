find_package(fmt CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS filesystem)

add_library(injdbgspawn SHARED injdbgspawn.cpp)
target_link_libraries(injdbgspawn PRIVATE boost_filesystem frida-gum fmt magic_enum subprocess)
