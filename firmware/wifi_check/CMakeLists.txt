add_executable(wifi_check main.c)
target_include_directories(wifi_check PRIVATE ${CMAKE_CURRENT_LIST_DIR})
target_compile_definitions(wifi_check PRIVATE
    WIFI_SSID=\"${WIFI_SSID}\"
    WIFI_PASSWORD=\"${WIFI_PASSWORD}\")
target_link_libraries(wifi_check pico_stdlib pico_cyw43_arch_lwip_threadsafe_background)
pico_enable_stdio_usb(wifi_check 1)
pico_enable_stdio_uart(wifi_check 0)
pico_add_extra_outputs(wifi_check)
