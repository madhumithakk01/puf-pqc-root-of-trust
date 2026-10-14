# Application image. Built once per version; the signed manifest and SBI1 container
# are added by tools/vendor/vendor_cli sign-image. Not a TBYB image: the RoT owns the trial.
# APP_VERSION selects the DSP variant: 1.0.0, 1.1.0 or 1.2.0 (the deliberate regression).

set(APP_VERSION "1.1.0" CACHE STRING "Application version")
if(APP_VERSION VERSION_LESS 1.1)
    set(APP_DSP 0)
elseif(APP_VERSION VERSION_LESS 1.2)
    set(APP_DSP 1)
else()
    set(APP_DSP 2)
endif()
string(REGEX REPLACE "^([0-9]+)\\.([0-9]+)\\.([0-9]+).*" "\\1" APP_MAJOR "${APP_VERSION}")
set(APP_SVN_DEFAULT 1)
if(APP_DSP EQUAL 1)
    set(APP_SVN_DEFAULT 2)
elseif(APP_DSP EQUAL 2)
    set(APP_SVN_DEFAULT 3)
endif()
set(APP_SVN ${APP_SVN_DEFAULT} CACHE STRING "Security version this build believes it is")

set(APP_TRANSPORT_USB 0 CACHE STRING "1: serve PQW1 over USB lines instead of Wi-Fi")
set(APP_SRC ${REPO_ROOT}/app)
add_executable(app main.c
    ${APP_SRC}/sensor/max30102.c ${APP_SRC}/dsp/dsp.c ${APP_SRC}/health/selftest.c
    ${APP_SRC}/golden/golden_trace.c ${APP_SRC}/proto/pqw1.c ${APP_SRC}/proto/app_server.c)
target_include_directories(app PRIVATE ${CMAKE_CURRENT_LIST_DIR} ${REPO_ROOT}/firmware/common ${APP_SRC})
target_compile_definitions(app PRIVATE
    APP_VERSION_STR=\"${APP_VERSION}\" APP_DSP_VARIANT=${APP_DSP} APP_SVN=${APP_SVN} APP_TRANSPORT_USB=${APP_TRANSPORT_USB}
    WIFI_SSID=\"${WIFI_SSID}\" WIFI_PASSWORD=\"${WIFI_PASSWORD}\")

# program RAM stops below the handoff region (0x2007C000)
pico_set_linker_script_var(app RAM_LENGTH 496k)

target_link_libraries(app pico_stdlib hardware_i2c hardware_flash hardware_watchdog
    pico_cyw43_arch_lwip_threadsafe_background rot_shared)
pico_enable_stdio_usb(app 1)
pico_enable_stdio_uart(app 0)
pico_add_extra_outputs(app)
