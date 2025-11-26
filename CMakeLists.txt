cmake_minimum_required(VERSION 3.10)
project(MyProject C)

set(CMAKE_C_STANDARD 11)

# Include directories (adjust if your headers are elsewhere)
include_directories(${PROJECT_SOURCE_DIR}/include)

# Gather all source files (adjust path if needed)
file(GLOB SOURCES "${PROJECT_SOURCE_DIR}/source/*.c")

# Create executable
add_executable(pwd_manager ${SOURCES})

# Link libraries: libsodium and math
target_link_libraries(pwd_manager sodium m)
