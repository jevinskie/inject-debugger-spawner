find_package(Boost REQUIRED)

add_library(injdbgspawn SHARED injdbgspawn.cpp)
target_link_libraries(injdbgspawn PRIVATE debugbreak magic_enum)
target_compile_options(injdbgspawn PRIVATE -g)
# some software likes to bundle their own ancient libcs..
target_link_options(injdbgspawn PRIVATE -static-libgcc -static-libstdc++)
