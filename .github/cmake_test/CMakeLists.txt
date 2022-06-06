cmake_minimum_required(VERSION 3.10)
project(RizinCMakeTest VERSION 1.0.0)

find_package(Rizin COMPONENTS Core)
add_executable(rizin_cmake_test rz_core_test.c)
target_link_libraries(rizin_cmake_test PRIVATE Rizin::Core)
