cmake_minimum_required(VERSION 3.13)

# One Pico 2 W on the RP2350's Hazard3 RISC-V cores. Arm fallback:
#   cmake -S firmware -B build/fw-arm -G Ninja -DPICO_PLATFORM=rp2350-arm-s
set(PICO_BOARD pico2_w CACHE STRING "Board")
set(PICO_PLATFORM rp2350-riscv CACHE STRING "Platform")

include(pico_sdk_import.cmake)

project(puf_pqc_firmware C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

# Wi-Fi credentials live in an untracked file: set(WIFI_SSID "...") set(WIFI_PASSWORD "...")
if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/wifi.cmake)
    include(${CMAKE_CURRENT_LIST_DIR}/wifi.cmake)
endif()
if(NOT DEFINED WIFI_SSID)
    set(WIFI_SSID "unset")
    set(WIFI_PASSWORD "unset")
endif()

set(REPO_ROOT ${CMAKE_CURRENT_LIST_DIR}/..)

add_compile_options(-Wall -Wextra)

add_subdirectory(hello)
add_subdirectory(i2c_check)
add_subdirectory(wifi_check)
