cmake_minimum_required(VERSION 3.28)

project(binaryslammer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(glfw3 CONFIG REQUIRED)
find_package(OpenGL REQUIRED)
find_package(Zydis CONFIG REQUIRED)
find_package(LLVM CONFIG REQUIRED)
message(STATUS "LLVM ${LLVM_PACKAGE_VERSION} found at ${LLVM_DIR}")
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

#set(CMAKE_BUILD_TYPE Debug)
set (CMAKE_BUILD_TYPE Release)

add_executable(app)

file(GLOB_RECURSE app_SOURCES
  "src/*.cpp"
  "src/*.hpp"
  "src/*.h"
  "src/*.inl"

  "incl/*.cpp"
  "incl/*.hpp"
  "incl/*.h"
  "incl/*.inl"
)

target_sources(app PRIVATE ${app_SOURCES})

target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/incl
)

llvm_map_components_to_libnames(llvm_libs
  core analysis transformutils scalaropts instcombine ipo support passes)

target_link_libraries(app PRIVATE
  OpenGL::GL
  glfw
  Zydis::Zydis
  ${llvm_libs}
)

if (MSVC)
  target_compile_options(app PRIVATE
    /W3
    /MP
    /ZI
  )
else()
  target_compile_options(app PRIVATE
    -Wall
    -Wextra
    -Wpedantic
  )
endif()
