cmake_minimum_required(VERSION 3.28)

project(binaryslammer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(glfw3 CONFIG REQUIRED)
find_package(OpenGL REQUIRED)
find_package(Zydis CONFIG REQUIRED)

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

target_link_libraries(app PRIVATE
  OpenGL::GL
  glfw
  Zydis::Zydis
)

if (MSVC)
  target_compile_options(app PRIVATE
    /W3
    /MP
    /WX
    /ZI
  )
else()
  target_compile_options(app PRIVATE
    -Wall
    -Wextra
    -Wpedantic
  )
endif()
