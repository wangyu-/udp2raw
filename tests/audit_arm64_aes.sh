#!/usr/bin/env bash
set -eu

if [[ $# -lt 5 ]]; then
    echo "usage: $0 PORTABLE HYBRID CRYPTO_OBJECT BASELINE_OBJECT..." >&2
    exit 2
fi

portable=$1
hybrid=$2
crypto_object=$3
shift 3

objdump_tool=${OBJDUMP:-objdump}
nm_tool=${NM:-nm}
readelf_tool=${READELF:-readelf}
opcode_pattern='\b(aese|aesmc|aesd|aesimc)\b'

for binary in "$portable" "$hybrid"; do
    "$readelf_tool" -h "$binary" | grep -q 'Class:.*ELF64'
    "$readelf_tool" -h "$binary" | grep -q 'Data:.*little endian'
    "$readelf_tool" -h "$binary" | grep -q 'Machine:.*AArch64'
    if "$readelf_tool" -l "$binary" | grep -q 'INTERP'; then
        echo "$binary has a dynamic interpreter" >&2
        exit 1
    fi
    if "$readelf_tool" -d "$binary" 2>/dev/null | grep -q 'NEEDED'; then
        echo "$binary has a dynamic dependency" >&2
        exit 1
    fi
done

if "$objdump_tool" -d "$portable" | grep -Eq "$opcode_pattern"; then
    echo "$portable contains an ARM AES opcode" >&2
    exit 1
fi

for baseline_object in "$@"; do
    if "$objdump_tool" -d "$baseline_object" | grep -Eq "$opcode_pattern"; then
        echo "$baseline_object contains an ARM AES opcode" >&2
        exit 1
    fi
done

for opcode in aese aesmc aesd aesimc; do
    if ! "$objdump_tool" -d "$crypto_object" | grep -qw "$opcode"; then
        echo "$crypto_object does not contain $opcode" >&2
        exit 1
    fi
done

crypto_opcode_count=$(
    "$objdump_tool" -d "$crypto_object" | grep -Ec "$opcode_pattern"
)
hybrid_opcode_count=$(
    "$objdump_tool" -d "$hybrid" | grep -Ec "$opcode_pattern"
)
hybrid_leaf_opcode_count=$(
    "$objdump_tool" -d --disassemble=aesarm_crypt_ecb "$hybrid" |
        grep -Ec "$opcode_pattern"
)
if [[ $crypto_opcode_count -ne $hybrid_opcode_count ||
      $hybrid_opcode_count -ne $hybrid_leaf_opcode_count ]]; then
    echo "ARM AES opcodes escaped aesarm_crypt_ecb" >&2
    exit 1
fi

if "$nm_tool" -C "$hybrid" | grep -qi 'vpaes'; then
    echo "$hybrid contains a VPAES symbol" >&2
    exit 1
fi
if ! "$nm_tool" -C "$hybrid" | grep -q 'aes_faster_c::'; then
    echo "$hybrid does not contain the portable C backend" >&2
    exit 1
fi
if ! "$nm_tool" -C "$hybrid" | grep -q 'aesarm_backend::'; then
    echo "$hybrid does not contain the ARMv8 Crypto backend" >&2
    exit 1
fi
if "$nm_tool" "$portable" | grep -q 'aesarm_crypt_ecb'; then
    echo "$portable contains the ARMv8 Crypto backend" >&2
    exit 1
fi

public_symbols=(
    AES_support_hwaccel
    AES_backend_name
    AES_ECB_encrypt_buffer
    AES_ECB_decrypt_buffer
    AES_CBC_encrypt_buffer
    AES_CBC_decrypt_buffer
    AES_CFB_encrypt_buffer
    AES_CFB_decrypt_buffer
)
for symbol in "${public_symbols[@]}"; do
    symbol_count=$(
        "$nm_tool" -g --defined-only "$hybrid" |
            awk -v symbol="$symbol" '$3 == symbol { count++ } END { print count + 0 }'
    )
    if [[ $symbol_count -ne 1 ]]; then
        echo "$hybrid defines $symbol $symbol_count times" >&2
        exit 1
    fi
done

echo "ARM64 AES binary audit passed"
echo "crypto_opcodes=$hybrid_opcode_count confined_to=aesarm_crypt_ecb"
echo "fallback=portable-c vpaes=absent linkage=static"
