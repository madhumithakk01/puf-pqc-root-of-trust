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

# RoT build options
set(ROT_CONSOLE_WAIT_MS 1500 CACHE STRING "Milliseconds the RoT waits for a USB console")
set(ROT_STABLE_PAIRS 0 CACHE STRING "Restrict enrollment to pairs stable in all reads")
set(ROT_SIM_PUF 0 CACHE STRING "Mark the build as using a simulated PUF")
set(ROT_SELFTEST 0 CACHE STRING "Run the known-answer self-test at RoT start")
set(ROT_PMP_LOCK 0 CACHE STRING "Lock a PMP region over the OTP registers before chaining")
execute_process(COMMAND git -C ${REPO_ROOT} rev-parse --short=19 HEAD
                OUTPUT_VARIABLE GIT_SHA OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
if(NOT GIT_SHA)
    set(GIT_SHA "0000000000000000000")
endif()
string(SUBSTRING "${GIT_SHA}0000000000000000000" 0 19 ROT_BUILD_ID)

add_compile_options(-Wall -Wextra)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/rot_core.cmake)

add_subdirectory(hello)
add_subdirectory(i2c_check)
add_subdirectory(wifi_check)
add_subdirectory(rot)
add_subdirectory(app)
add_subdirectory(charz)
add_subdirectory(bench)
add_subdirectory(recorder)
add_subdirectory(spike_chain)
