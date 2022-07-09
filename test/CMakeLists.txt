add_executable(simple simple.cpp)

add_executable(subproc subproc.cpp)
target_compile_options(subproc PRIVATE -fexceptions)
target_link_libraries(subproc PRIVATE subprocess)
