cc_cross=/home/wangyu/Desktop/arm-2014.05/bin/arm-none-linux-gnueabi-g++
cc_local=g++
cc_mips24kc_be=/toolchains/lede-sdk-17.01.2-ar71xx-generic_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-mips_24kc_gcc-5.4.0_musl-1.1.16/bin/mips-openwrt-linux-musl-g++
cc_mips24kc_le=/toolchains/lede-sdk-17.01.2-ramips-mt7621_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.16/bin/mipsel-openwrt-linux-musl-g++
cc_arm= /toolchains/lede-sdk-17.01.2-bcm53xx_gcc-5.4.0_musl-1.1.16_eabi.Linux-x86_64/staging_dir/toolchain-arm_cortex-a9_gcc-5.4.0_musl-1.1.16_eabi/bin/arm-openwrt-linux-c++
cc_arm64 ?= aarch64-linux-gnu-g++
cc_mingw_cross=i686-w64-mingw32-g++-posix
cc_mac_cross=o64-clang++ -stdlib=libc++
cc_x86=/toolchains/lede-sdk-17.01.2-x86-generic_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-i386_pentium4_gcc-5.4.0_musl-1.1.16/bin/i486-openwrt-linux-c++
cc_amd64=/toolchains/lede-sdk-17.01.2-x86-64_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-x86_64_gcc-5.4.0_musl-1.1.16/bin/x86_64-openwrt-linux-c++
#cc_bcm2708=/home/wangyu/raspberry/tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian/bin/arm-linux-gnueabihf-g++ 


FLAGS= -std=c++11   -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -Wno-missing-field-initializers ${OPT}
GIT_VERSION ?= $(shell git rev-parse HEAD 2>/dev/null)

COMMON=main.cpp lib/md5.cpp lib/pbkdf2-sha1.cpp lib/pbkdf2-sha256.cpp encrypt.cpp log.cpp network.cpp common.cpp  connection.cpp misc.cpp fd_manager.cpp client.cpp server.cpp -lpthread

SOURCES0= $(COMMON) lib/aes_faster_c/aes.cpp lib/aes_faster_c/backend.cpp lib/aes_faster_c/wrapper.cpp
SOURCES= ${SOURCES0} my_ev.cpp -isystem libev
SOURCES_AES_ACC= $(COMMON) $(wildcard lib/aes_acc/aes*.c) my_ev.cpp -isystem libev
SOURCES_ARM64_HYBRID= $(COMMON) lib/aes_faster_c/aes.cpp lib/aes_faster_c/backend.cpp my_ev.cpp -isystem libev
PCAP="-lpcap"
MP="-DUDP2RAW_MP"

ARM64_BASE_FLAGS ?= -march=armv8-a
ARM64_CRYPTO_FLAGS ?= -march=armv8-a+crypto
ARM64_NO_LTO_FLAGS ?= -fno-lto
ARM64_AES_VARIANT_FLAGS ?=
ARM64_BUILD_DIR ?= .build/arm64_hw_aes
ARM64_AESARM_OBJ= ${ARM64_BUILD_DIR}/aesarm.o
ARM64_AESARM_CPUID_OBJ= ${ARM64_BUILD_DIR}/aesarm_cpuid.o
ARM64_AESARM_BACKEND_OBJ= ${ARM64_BUILD_DIR}/aesarm_backend.o
ARM64_AESARM_DISPATCH_OBJ= ${ARM64_BUILD_DIR}/aesarm_dispatch.o
ARM64_AES_TEST_SOURCE= tests/aes_backend_test.cpp
ARM64_AES_TEST_PORTABLE= ${ARM64_BUILD_DIR}/aes_backend_test_portable
ARM64_AES_TEST_HYBRID= ${ARM64_BUILD_DIR}/aes_backend_test_hybrid
ARM64_TARGETS= arm64 arm64_hw_aes


NAME=udp2raw

TARGETS=amd64 arm amd64_hw_aes arm_asm_aes mips24kc_be mips24kc_be_asm_aes x86 x86_asm_aes mips24kc_le mips24kc_le_asm_aes

TAR=${NAME}_binaries.tar.gz `echo ${TARGETS}|sed -r 's/([^ ]+)/${NAME}_\1/g'` version.txt

TARGETS_MP= mingw_cross mingw_cross_wepoll mac_cross

export STAGING_DIR=/tmp/    #just for supress warning of staging_dir not define

# targets for nativei (non-cross) compile 
all:git_version
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt -ggdb -static -O2

#dynamic link
dynamic: git_version
	${cc_local}   -o ${NAME}_$@          -I. ${SOURCES} ${FLAGS} -lrt -O2

#targes for general cross compile

cross:git_version
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} ${FLAGS} -lrt -O2

cross2:git_version
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} ${FLAGS} -lrt -static -lgcc_eh -O2

cross3:git_version
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} ${FLAGS} -lrt -static -O2

#targets only for debug purpose
fast: git_version
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt -ggdb
debug: git_version
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt -Wformat-nonliteral -D MY_DEBUG  -ggdb
debug2: git_version
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt -Wformat-nonliteral -ggdb -fsanitize=address

#targets only for 'make release'

mips24kc_be: git_version
	${cc_mips24kc_be}  -o ${NAME}_$@   -I. ${SOURCES} ${FLAGS} -lrt -lgcc_eh -static -O2
mips24kc_be_asm_aes: git_version
	${cc_mips24kc_be}  -o ${NAME}_$@   -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -lgcc_eh -static -O2 lib/aes_acc/asm/mips_be.S
mips24kc_le: git_version
	${cc_mips24kc_le}  -o ${NAME}_$@   -I. ${SOURCES} ${FLAGS} -lrt -lgcc_eh -static -O2
mips24kc_le_asm_aes: git_version
	${cc_mips24kc_le}  -o ${NAME}_$@   -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -lgcc_eh -static -O2 lib/aes_acc/asm/mips.S
amd64:git_version
	${cc_amd64}   -o ${NAME}_$@    -I. ${SOURCES} ${FLAGS} -lrt -static -O2 -lgcc_eh -ggdb
amd64_hw_aes:git_version
	${cc_amd64}   -o ${NAME}_$@   -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -static -O2 lib/aes_acc/asm/x64.S -lgcc_eh -ggdb
x86:git_version
	${cc_x86}   -o ${NAME}_$@      -I. ${SOURCES} ${FLAGS} -lrt -static -O2 -lgcc_eh -ggdb
x86_asm_aes:git_version
	${cc_x86}   -o ${NAME}_$@    -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -static -O2 lib/aes_acc/asm/x86.S -lgcc_eh -ggdb
arm:git_version
	${cc_arm}   -o ${NAME}_$@      -I. ${SOURCES} ${FLAGS} -lrt -static -O2 -lgcc_eh
arm_asm_aes:git_version
	${cc_arm}   -o ${NAME}_$@    -I. ${SOURCES_AES_ACC} ${FLAGS} -lrt -static -O2 lib/aes_acc/asm/arm.S -lgcc_eh

arm64:git_version
	${cc_arm64} -o ${NAME}_$@ -I. ${SOURCES} ${FLAGS} ${ARM64_BASE_FLAGS} ${ARM64_NO_LTO_FLAGS} -lrt -static -O2 -lgcc_eh

${ARM64_AESARM_OBJ}: lib/aes_acc/aesarm.c lib/aes_acc/aesarm.h
	mkdir -p ${ARM64_BUILD_DIR}
	${cc_arm64} -o $@ -I. ${FLAGS} ${ARM64_CRYPTO_FLAGS} ${ARM64_NO_LTO_FLAGS} -DHAVE_ARM64 -O2 -c $<

${ARM64_AESARM_CPUID_OBJ}: lib/aes_acc/aesarm_cpuid.c lib/aes_acc/aesarm.h
	mkdir -p ${ARM64_BUILD_DIR}
	${cc_arm64} -o $@ -I. ${FLAGS} ${ARM64_BASE_FLAGS} ${ARM64_NO_LTO_FLAGS} -DHAVE_ARM64 -O2 -c $<

${ARM64_AESARM_BACKEND_OBJ}: lib/aes_acc/aesarm_backend.cpp lib/aes_acc/aesarm_backend.h lib/aes_acc/aesarm.h lib/aes_acc/aesarm_table.h lib/aes-keysize.h
	mkdir -p ${ARM64_BUILD_DIR}
	${cc_arm64} -o $@ -I. ${FLAGS} ${ARM64_AES_VARIANT_FLAGS} ${ARM64_BASE_FLAGS} ${ARM64_NO_LTO_FLAGS} -DHAVE_ARM64 -O2 -c $<

${ARM64_AESARM_DISPATCH_OBJ}: lib/aes_acc/aesarm_dispatch.cpp lib/aes_acc/aesarm.h lib/aes_acc/aesarm_backend.h lib/aes_faster_c/backend.h lib/aes-common.h
	mkdir -p ${ARM64_BUILD_DIR}
	${cc_arm64} -o $@ -I. ${FLAGS} ${ARM64_BASE_FLAGS} ${ARM64_NO_LTO_FLAGS} -DHAVE_ARM64 -O2 -c $<

arm64_hw_aes:git_version ${ARM64_AESARM_OBJ} ${ARM64_AESARM_CPUID_OBJ} ${ARM64_AESARM_BACKEND_OBJ} ${ARM64_AESARM_DISPATCH_OBJ}
	${cc_arm64} -o ${NAME}_$@ -I. ${SOURCES_ARM64_HYBRID} ${ARM64_AESARM_CPUID_OBJ} ${ARM64_AESARM_BACKEND_OBJ} ${ARM64_AESARM_DISPATCH_OBJ} ${ARM64_AESARM_OBJ} ${FLAGS} ${ARM64_BASE_FLAGS} ${ARM64_NO_LTO_FLAGS} -DHAVE_ARM64 -lrt -static -O2 -lgcc_eh

${ARM64_AES_TEST_PORTABLE}: ${ARM64_AES_TEST_SOURCE} lib/aes_faster_c/aes.cpp lib/aes_faster_c/backend.cpp lib/aes_faster_c/wrapper.cpp
	mkdir -p ${ARM64_BUILD_DIR}
	${cc_arm64} -o $@ -I. $^ ${FLAGS} ${ARM64_AES_VARIANT_FLAGS} ${ARM64_BASE_FLAGS} ${ARM64_NO_LTO_FLAGS} -static -O2 -pthread

${ARM64_AES_TEST_HYBRID}: ${ARM64_AES_TEST_SOURCE} lib/aes_faster_c/aes.cpp lib/aes_faster_c/backend.cpp ${ARM64_AESARM_CPUID_OBJ} ${ARM64_AESARM_BACKEND_OBJ} ${ARM64_AESARM_DISPATCH_OBJ} ${ARM64_AESARM_OBJ}
	mkdir -p ${ARM64_BUILD_DIR}
	${cc_arm64} -o $@ -I. ${ARM64_AES_TEST_SOURCE} lib/aes_faster_c/aes.cpp lib/aes_faster_c/backend.cpp ${ARM64_AESARM_CPUID_OBJ} ${ARM64_AESARM_BACKEND_OBJ} ${ARM64_AESARM_DISPATCH_OBJ} ${ARM64_AESARM_OBJ} ${FLAGS} ${ARM64_AES_VARIANT_FLAGS} ${ARM64_BASE_FLAGS} ${ARM64_NO_LTO_FLAGS} -DHAVE_ARM64 -static -O2 -pthread

test_arm64_aes: ${ARM64_AES_TEST_PORTABLE} ${ARM64_AES_TEST_HYBRID}
	@portable_output="$$( ${ARM64_AES_TEST_PORTABLE} --expect-hw=0 --expect-backend=portable-c )" || { printf '%s\n' "$$portable_output"; exit 1; }; \
	hw_argument=""; \
	if [ "${AES_EXPECT_HW}" = "1" ]; then hw_argument="--expect-hw=1 --expect-backend=armv8-crypto"; fi; \
	if [ "${AES_EXPECT_HW}" = "0" ]; then hw_argument="--expect-hw=0 --expect-backend=portable-c"; fi; \
	hw_output="$$( ${ARM64_AES_TEST_HYBRID} $$hw_argument )" || { printf '%s\n' "$$portable_output" "$$hw_output"; exit 1; }; \
	printf '%s\n' "$$portable_output" "$$hw_output"; \
	portable_digest="$$( printf '%s\n' "$$portable_output" | sed -n 's/^corpus_digest=//p' )"; \
	hw_digest="$$( printf '%s\n' "$$hw_output" | sed -n 's/^corpus_digest=//p' )"; \
	test -n "$$portable_digest" && test "$$portable_digest" = "$$hw_digest" || { echo "AES backend corpus digests differ"; exit 1; }

test_arm64_aes_all_key_sizes: test_arm64_aes
	${MAKE} ARM64_BUILD_DIR=.build/arm64_hw_aes_192 ARM64_AES_VARIANT_FLAGS=-DAES192=1 AES_EXPECT_HW=${AES_EXPECT_HW} test_arm64_aes
	${MAKE} ARM64_BUILD_DIR=.build/arm64_hw_aes_256 ARM64_AES_VARIANT_FLAGS=-DAES256=1 AES_EXPECT_HW=${AES_EXPECT_HW} test_arm64_aes

benchmark_arm64_aes: test_arm64_aes
	${ARM64_AES_TEST_PORTABLE} --expect-hw=0 --benchmark
	${ARM64_AES_TEST_HYBRID} $(if ${AES_EXPECT_HW},--expect-hw=${AES_EXPECT_HW},) --benchmark

audit_arm64_aes: arm64 arm64_hw_aes
	tests/audit_arm64_aes.sh ${NAME}_arm64 ${NAME}_arm64_hw_aes ${ARM64_AESARM_OBJ} ${ARM64_AESARM_CPUID_OBJ} ${ARM64_AESARM_BACKEND_OBJ} ${ARM64_AESARM_DISPATCH_OBJ}

release: ${TARGETS}
	cp git_version.h version.txt
	tar -zcvf ${TAR}

release_arm64: ${ARM64_TARGETS}
	cp git_version.h version.txt
	tar -zcvf ${NAME}_arm64_binaries.tar.gz `echo ${ARM64_TARGETS}|sed -r 's/([^ ]+)/${NAME}_\1/g'` version.txt

#targets for multi-platform version (native compile)
cygwin:git_version
	${cc_local}   -o ${NAME}_$@          -I. ${SOURCES} pcap_wrapper.cpp ${FLAGS} -lrt -ggdb -static -O2 -D_GNU_SOURCE ${MP}

mingw:git_version
	${cc_local}   -o ${NAME}_$@         -I. ${SOURCES} pcap_wrapper.cpp ${FLAGS} -ggdb -static -O2 -lws2_32 ${MP}

mingw_wepoll:git_version
	${cc_local}   -o ${NAME}_$@        -I. ${SOURCES0} pcap_wrapper.cpp ${FLAGS} -ggdb -static -O2 -DNO_LIBEV_EMBED -D_WIN32 -lev -lws2_32 ${MP}

linux:git_version
	${cc_local}   -o ${NAME}_$@          -I. ${SOURCES} ${PCAP} ${FLAGS} -lrt -ggdb -static -O2 ${MP}

freebsd:git_version
	${cc_local}   -o ${NAME}_$@        -I. ${SOURCES} ${PCAP} ${FLAGS} -lrt -ggdb -static -libverbs -O2 ${MP}

mac:git_version
	${cc_local}   -o ${NAME}_$@        -I. ${SOURCES} ${PCAP} ${FLAGS} -ggdb -O2 ${MP}

#targets for multi-platform version (cross compile)

mingw_cross:git_version
	${cc_mingw_cross}   -o ${NAME}_mp.exe          -I. ${SOURCES} pcap_wrapper.cpp ${FLAGS} -ggdb -static -O2 -lws2_32 ${MP}

mingw_cross_wepoll:git_version
	${cc_mingw_cross}   -o ${NAME}_mp_wepoll.exe   -I. ${SOURCES0} pcap_wrapper.cpp ${FLAGS} -ggdb -static -O2 -DNO_LIBEV_EMBED -D_WIN32 -lev -lws2_32 ${MP}

mac_cross:git_version
	${cc_mac_cross}   -o ${NAME}_mp_mac            -I. ${SOURCES} ${PCAP} ${FLAGS} -ggdb -O2 ${MP}

release_mp:${TARGETS_MP}
	cp git_version.h version.txt
	tar -zcvf ${NAME}_mp_binaries.tar.gz ${NAME}_mp.exe ${NAME}_mp_wepoll.exe ${NAME}_mp_mac version.txt


clean:	
	rm -f ${TAR}
	rm -f ${NAME} ${NAME}_cross ${NAME}.exe ${NAME}_wepoll.exe ${NAME}_mac
	rm -f ${NAME}_arm64 ${NAME}_arm64_hw_aes ${NAME}_arm64_binaries.tar.gz
	rm -rf .build/arm64_hw_aes .build/arm64_hw_aes_192 .build/arm64_hw_aes_256
	rm -f ${NAME}_mp_binaries.tar.gz ${NAME}_mp.exe ${NAME}_mp_wepoll.exe ${NAME}_mp_mac
	rm -f git_version.h

git_version:
	    echo "const char *gitversion = \"${GIT_VERSION}\";" > git_version.h

.PHONY: arm64 arm64_hw_aes release_arm64 test_arm64_aes test_arm64_aes_all_key_sizes benchmark_arm64_aes audit_arm64_aes clean git_version
