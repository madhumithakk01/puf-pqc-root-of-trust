# RoT image: flash offset 0, unpartitioned, with the partition table in its block loop.
# Memory layout (implementation guide, section 3.5): program RAM 320 KB, the core-0
# stack in a 96 KB region at 0x20050000, and nothing else linked above that.

add_executable(rot main.c ../platform/rp2350/rp2350_platform.c)
target_include_directories(rot PRIVATE ${CMAKE_CURRENT_LIST_DIR}/..)
target_compile_definitions(rot PRIVATE
    PICO_STACK_SIZE=0x18000
    PICO_HEAP_SIZE=0x2000
    ROT_BUILD_ID=\"${ROT_BUILD_ID}\"
    ROT_CONSOLE_WAIT_MS=${ROT_CONSOLE_WAIT_MS}
    ROT_STABLE_PAIRS=${ROT_STABLE_PAIRS}
    ROT_SIM_PUF=${ROT_SIM_PUF}
    ROT_PMP_LOCK=${ROT_PMP_LOCK})

pico_set_linker_script_var(rot RAM_LENGTH 320k)
pico_set_linker_script_var(rot SCRATCH_Y_ORIGIN 0x20050000)
pico_set_linker_script_var(rot SCRATCH_Y_LENGTH 96k)

target_link_libraries(rot pico_stdlib hardware_adc hardware_watchdog hardware_flash
    hardware_resets pico_low_power pico_aon_timer rot_core)
pico_enable_stdio_usb(rot 1)
pico_enable_stdio_uart(rot 0)
pico_embed_pt_in_binary(rot ${CMAKE_CURRENT_LIST_DIR}/../pt/pt.json)
pico_set_uf2_family(rot "absolute")
pico_add_extra_outputs(rot)
