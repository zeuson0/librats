# Normal and occlum mode
set(CMAKE_C_FLAGS "-std=gnu11 -fPIC")
set(RATS_LDFLAGS "-fPIC -Bsymbolic -ldl")

if(OCCLUM)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DOCCLUM")
endif()

if (NOT WASM)
    if(DEBUG)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb -O0")
    else()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
    endif()
endif()

# SGX mode
if(SGX)
    if(SGX_HW)
        set(SGX_URTS_LIB sgx_urts)
        set(SGX_USVC_LIB sgx_uae_service)
        set(SGX_TRTS_LIB sgx_trts)
        set(SGX_TSVC_LIB sgx_tservice)
    else()
        set(SGX_URTS_LIB sgx_urts_sim)
        set(SGX_USVC_LIB sgx_uae_service_sim)
        set(SGX_TRTS_LIB sgx_trts_sim)
        set(SGX_TSVC_LIB sgx_tservice_sim)
    endif()
    set(SGX_DACP_QL sgx_dcap_ql)
    set(SGX_DACP_QUOTEVERIFY sgx_dcap_quoteverify)
    set(SGX_DCAP_TVL sgx_dcap_tvl)

    set(APP_COMMON_FLAGS "-fPIC -Wno-attributes")

    if(SGX_DEBUG)
        set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -O0 -g")
        set(APP_COMMON_FLAGS "${APP_COMMON_FLAGS} -DDEBUG -UNDEBUG -UEDEBUG")
    elseif(SGX_PRERELEASE)
        set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -O2")
        set(APP_COMMON_FLAGS "${APP_COMMON_FLAGS} -DNDEBUG -DEDEBUG -UDEBUG")
    elseif(SGX_RELEASE)
        set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -O2")
        set(APP_COMMON_FLAGS "${APP_COMMON_FLAGS} -DNDEBUG -UEDEBUG -UDEBUG")
    endif()

    set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -Wall -Wextra -Winit-self")
    set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -Wpointer-arith -Wreturn-type -Waddress -Wsequence-point")
    set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -Wformat -Wformat-security -Wmissing-include-dirs -Wfloat-equal")
    set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -Wundef -Wshadow -Wcast-align")
    set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -Wredundant-decls")

    set(ENCLAVE_COMMON_FLAGS "-m64 -Wall -nostdinc -ffreestanding -fvisibility=hidden -fpic -fpie -ffunction-sections -fdata-sections")

    if(CMAKE_C_COMPILER_VERSION VERSION_LESS 4.9)
        set(ENCLAVE_COMMON_FLAGS "${ENCLAVE_COMMON_FLAGS} -fstack-protector")
    else()
        set(ENCLAVE_COMMON_FLAGS "${ENCLAVE_COMMON_FLAGS} -fstack-protector-strong")
    endif()

    set(SGX_COMMON_CFLAGS "${SGX_COMMON_FLAGS} -Wstrict-prototypes -Wunsuffixed-float-constants -Wno-implicit-function-declaration -std=c11")
    set(SGX_COMMON_CXXFLAGS "${SGX_COMMON_FLAGS} -Wnon-virtual-dtor -std=c++11")

    set(ENCLAVE_INCLUDES "${SGX_INCLUDE}" "${SGX_TLIBC_INCLUDE}" "${SGX_LIBCXX_INCLUDE}" "/usr/include")
    set(ENCLAVE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} ${ENCLAVE_COMMON_FLAGS}")
    set(ENCLAVE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SGX_COMMON_CXXFLAGS} ${ENCLAVE_COMMON_FLAGS} -nostdinc++")

    set(APP_INCLUDES "${SGX_INCLUDE}")
    set(APP_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} ${APP_COMMON_FLAGS}")
    set(APP_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SGX_COMMON_CXXFLAGS} ${APP_COMMON_FLAGS}")
endif()

if (WASM)
    set(WASM_SRCS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/wasm/emscripten)
    set(WASM_BUILD_DIR ${CMAKE_BINARY_DIR}/wasm)
    set(SEV_DEFAULT_DIR "/opt/sev")
    set(ASK_ARK_PATH_SITE "https://developer.amd.com/wp-content/resources")
    set(ASK_ARK_BASE "ask_ark_")
    set(ASK_ARK_NAPLES_FILE "${ASK_ARK_BASE}naples.cert")
    set(ASK_ARK_ROME_FILE "${ASK_ARK_BASE}rome.cert")
    set(ASK_ARK_MILAN_FILE "${ASK_ARK_BASE}milan.cert")
    execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory ${WASM_BUILD_DIR})
    set(WASM_COMMON_FLAGS "-sALLOW_MEMORY_GROWTH=1 -sSAFE_HEAP=1 -fexceptions -fPIC -Wno-limited-postlink-optimizations -Wno-linkflags")
    set(WASM_MAIN_BASE_FLAGS "-sMAIN_MODULE=2 -fPIC -fexceptions")
    if (DEBUG)
        set(WASM_COMMON_FLAGS "${WASM_COMMON_FLAGS} -O0 -gsource-map -sSTACK_OVERFLOW_CHECK=1 -DWASM_TEST")
        set(WASM_MAIN_BASE_FLAGS "${WASM_MAIN_BASE_FLAGS} -DWASM_TEST")
    else()
        set(WASM_COMMON_FLAGS "${WASM_COMMON_FLAGS} -O3")
    endif()
    set(WASM_MAIN_NORMAL_FLAGS "${WASM_COMMON_FLAGS} -sMAIN_MODULE=2 --use-preload-plugins -lembind")
    set(WASM_MAIN_ASYNC_FLAGS "${WASM_MAIN_NORMAL_FLAGS} -gsource-map -sASYNCIFY -sASYNCIFY_IMPORTS=['dcap_fetch_proxy']") 
    set(WASM_SIDE_NORMAL_FLAGS "${WASM_COMMON_FLAGS} -sSIDE_MODULE=2")
    set(WASM_SIDE_ASYNC_FLAGS "${WASM_SIDE_NORMAL_FLAGS} -sASYNCIFY")
endif()