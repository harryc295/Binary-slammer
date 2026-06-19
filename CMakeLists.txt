cmake_minimum_required(VERSION 3.28)

# Static triplet so the release exe has no Zydis.dll/glfw3.dll to ship alongside it.
if(WIN32 AND NOT DEFINED VCPKG_TARGET_TRIPLET)
  set(VCPKG_TARGET_TRIPLET "x64-windows-static" CACHE STRING "")
endif()

project(binaryslammer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

find_package(glfw3 CONFIG REQUIRED)
find_package(OpenGL REQUIRED)
find_package(Zydis CONFIG REQUIRED)
find_package(LLVM CONFIG)
find_package(unofficial-yara CONFIG QUIET)
if(LLVM_FOUND)
  message(STATUS "LLVM ${LLVM_PACKAGE_VERSION} found at ${LLVM_DIR}")
  include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
  add_definitions(${LLVM_DEFINITIONS})
else()
  message(STATUS "LLVM not found — LLVM IR panel disabled")
endif()

set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

#set(CMAKE_BUILD_TYPE Debug)
set (CMAKE_BUILD_TYPE Release)

if(WIN32)
  enable_language(RC)
endif()

add_executable(app)
set_target_properties(app PROPERTIES OUTPUT_NAME "binaryslammer")

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

if(WIN32)
  list(APPEND app_SOURCES resources.rc)
endif()

target_sources(app PRIVATE ${app_SOURCES})

target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/incl
)

target_link_libraries(app PRIVATE
  OpenGL::GL
  glfw
  Zydis::Zydis
)

if(WIN32)
  target_link_libraries(app PRIVATE shell32 ole32)
endif()

if(LLVM_FOUND)
  llvm_map_components_to_libnames(llvm_libs
    core analysis transformutils scalaropts instcombine ipo support passes)
  target_link_libraries(app PRIVATE ${llvm_libs})
  target_compile_definitions(app PRIVATE HAVE_LLVM)
endif()

if(unofficial-yara_FOUND)
  message(STATUS "YARA found — enabling YARA integration")
  target_link_libraries(app PRIVATE unofficial::yara::libyara)
  target_compile_definitions(app PRIVATE HAVE_YARA)
else()
  message(STATUS "YARA not found — YARA panel will show enable instructions")
endif()

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
