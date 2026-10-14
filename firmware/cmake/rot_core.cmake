# The portable RoT core and the PQC primitives it needs, as static libraries.
#
#   pqc_mldsa44   PQClean ML-DSA-44 reference C
#   pqc_mlkem512  PQClean ML-KEM-512 reference C
#   pqc_common    fips202 (SHAKE256); randombytes comes from src/rot/rot_rng.c
#   rot_core      everything under src/ the RoT links
#   rot_shared    the few public-format helpers the application shares (no crypto)

set(PQC ${REPO_ROOT}/third_party/pqclean)

file(GLOB MLDSA_SRCS ${PQC}/crypto_sign/ml-dsa-44/clean/*.c)
file(GLOB MLKEM_SRCS ${PQC}/crypto_kem/ml-kem-512/clean/*.c)

add_library(pqc_common STATIC ${PQC}/common/fips202.c)
target_include_directories(pqc_common PUBLIC ${PQC}/common)

add_library(pqc_mldsa44 STATIC ${MLDSA_SRCS})
target_include_directories(pqc_mldsa44 PUBLIC ${PQC}/crypto_sign/ml-dsa-44/clean)
target_link_libraries(pqc_mldsa44 PUBLIC pqc_common)

add_library(pqc_mlkem512 STATIC ${MLKEM_SRCS})
target_include_directories(pqc_mlkem512 PUBLIC ${PQC}/crypto_kem/ml-kem-512/clean)
target_link_libraries(pqc_mlkem512 PUBLIC pqc_common)

# PQClean is built as upstream does, without the project's warning flags.
foreach(t pqc_common pqc_mldsa44 pqc_mlkem512)
    target_compile_options(${t} PRIVATE -O2 -w)
endforeach()

set(SRC ${REPO_ROOT}/src)
add_library(rot_core STATIC
    ${SRC}/rot/rot_anchor.c ${SRC}/rot/rot_boot.c ${SRC}/rot/rot_counter.c ${SRC}/rot/rot_crc32.c
    ${SRC}/rot/rot_enroll.c ${SRC}/rot/rot_flash.c ${SRC}/rot/rot_handoff.c ${SRC}/rot/rot_helper.c
    ${SRC}/rot/rot_hev.c ${SRC}/rot/rot_install.c ${SRC}/rot/rot_journal.c ${SRC}/rot/rot_keys.c
    ${SRC}/rot/rot_mailbox.c ${SRC}/rot/rot_mailbox_build.c ${SRC}/rot/rot_receipt.c
    ${SRC}/rot/rot_receipts.c ${SRC}/rot/rot_reset.c ${SRC}/rot/rot_rng.c ${SRC}/rot/rot_slot.c
    ${SRC}/rot/rot_trial.c ${SRC}/rot/rot_selftest.c
    ${SRC}/apm/apm.c ${SRC}/dlv/dlv.c ${SRC}/attest/attest2.c
    ${SRC}/ota/ota_aead.c
    ${SRC}/secure_boot/secure_boot.c ${SRC}/rollback/rollback.c ${SRC}/kdf/kdf.c
    ${SRC}/fuzzy/fuzzy_extractor.c ${SRC}/puf/vn_debias.c)
# rot_install.c and rot_boot.c include ota.h, api.h of ML-DSA-44 and declare the KEM entry points themselves
target_include_directories(rot_core PUBLIC ${SRC})
target_link_libraries(rot_core PUBLIC pqc_mldsa44 pqc_mlkem512 pqc_common)

add_library(rot_shared STATIC
    ${SRC}/rot/rot_crc32.c ${SRC}/rot/rot_mailbox_build.c ${SRC}/rot/rot_handoff.c ${SRC}/rot/rot_hev.c)
target_include_directories(rot_shared PUBLIC ${SRC} ${PQC}/crypto_sign/ml-dsa-44/clean ${PQC}/common)
