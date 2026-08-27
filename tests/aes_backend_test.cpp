#include "lib/aes-common.h"
#include "lib/aes-keysize.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace {

int failures = 0;

struct TestVectors {
    const char* key;
    const char* ecb;
    const char* cbc;
    const char* cfb;
};

const char kPlaintext[] =
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710";
const char kIv[] = "000102030405060708090a0b0c0d0e0f";

const TestVectors& test_vectors() {
#if UDP2RAW_AES_KEY_BITS == 256
    static const TestVectors vectors = {
        "603deb1015ca71be2b73aef0857d7781"
        "1f352c073b6108d72d9810a30914dff4",
        "f3eed1bdb5d2a03c064b5a7e3db181f8"
        "591ccb10d410ed26dc5ba74a31362870",
        "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
        "9cfc4e967edb808d679f777bc6702c7d"
        "39f23369a9d9bacfa530e26304231461"
        "b2eb05e2c39be9fcda6c19078c6a9d1b",
        "dc7e84bfda79164b7ecd8486985d3860"
        "39ffed143b28b1c832113c6331e5407b"
        "df10132415e54b92a13ed0a8267ae2f9"
        "75a385741ab9cef82031623d55b1e471",
    };
#elif UDP2RAW_AES_KEY_BITS == 192
    static const TestVectors vectors = {
        "8e73b0f7da0e6452c810f32b809079e5"
        "62f8ead2522c6b7b",
        "bd334f1d6e45f25ff712a214571fa5cc"
        "974104846d0ad3ad7734ecb3ecee4eef",
        "4f021db243bc633d7178183a9fa071e8"
        "b4d9ada9ad7dedf4e5e738763f69145a"
        "571b242012fb7ae07fa9baac3df102e0"
        "08b0e27988598881d920a9e64f5615cd",
        "cdc80d6fddf18cab34c25909c99a4174"
        "67ce7f7f81173621961a2b70171d3d7a"
        "2e1e8a1dd59b88b1c8e60fed1efac4c9"
        "c05f9f9ca9834fa042ae8fba584b09ff",
    };
#else
    static const TestVectors vectors = {
        "2b7e151628aed2a6abf7158809cf4f3c",
        "3ad77bb40d7a3660a89ecaf32466ef97"
        "f5d3d58503b9699de785895a96fdbaaf",
        "7649abac8119b246cee98e9b12e9197d"
        "5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e22229516"
        "3ff1caa1681fac09120eca307586e1a7",
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "c8a64537a0b3a93fcde3cdad9f1ce58b"
        "26751f67a3cbb140b1808cf187a4f4df"
        "c04b05357c5d1c0eeac4c66f9ff7f2e6",
    };
#endif
    return vectors;
}

std::vector<uint8_t> from_hex(const char* text) {
    std::vector<uint8_t> result;
    while (*text != '\0') {
        unsigned int value = 0;
        if (text[1] == '\0' || std::sscanf(text, "%2x", &value) != 1) {
            std::fprintf(stderr, "invalid hex test vector\n");
            return std::vector<uint8_t>();
        }
        result.push_back(static_cast<uint8_t>(value));
        text += 2;
    }
    return result;
}

void require_equal(const char* name, const std::vector<uint8_t>& actual,
                   const std::vector<uint8_t>& expected) {
    if (actual == expected) {
        return;
    }
    std::fprintf(stderr, "FAIL: %s\n", name);
    ++failures;
}

void require_true(const char* name, bool condition) {
    if (condition) {
        return;
    }
    std::fprintf(stderr, "FAIL: %s\n", name);
    ++failures;
}

std::vector<uint8_t> alternate_key() {
    std::vector<uint8_t> key(UDP2RAW_AES_KEY_BYTES);
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(0xa5U ^ (i * 29U));
    }
    return key;
}

void test_dispatch_initialization() {
    const size_t thread_count = 8;
    const size_t iterations = 10000;
    std::atomic<bool> consistent(true);
    std::vector<std::thread> threads;
    threads.reserve(thread_count);
    for (size_t thread = 0; thread < thread_count; ++thread) {
        threads.push_back(std::thread([&consistent]() {
            for (size_t i = 0; i < iterations; ++i) {
                const int hardware = AES_support_hwaccel();
                const char* backend = AES_backend_name();
                if ((hardware == 1 && std::strcmp(backend, "armv8-crypto") != 0) ||
                    (hardware == 0 && std::strcmp(backend, "portable-c") != 0)) {
                    consistent.store(false);
                }
            }
        }));
    }
    for (size_t thread = 0; thread < threads.size(); ++thread) {
        threads[thread].join();
    }
    require_true("thread-safe backend initialization", consistent.load());
}

void test_ecb() {
    const TestVectors& vectors = test_vectors();
    const std::vector<uint8_t> key = from_hex(vectors.key);
    const std::vector<uint8_t> plain = from_hex(kPlaintext);
    const std::vector<uint8_t> cipher = from_hex(vectors.ecb);
    if (key.size() != UDP2RAW_AES_KEY_BYTES || plain.size() < 32 ||
        cipher.size() != 32) {
        require_true("ECB test vector sizes", false);
        return;
    }
    const std::vector<uint8_t> plain1(plain.begin(), plain.begin() + 16);
    const std::vector<uint8_t> plain2(plain.begin() + 16, plain.begin() + 32);
    const std::vector<uint8_t> cipher1(cipher.begin(), cipher.begin() + 16);
    const std::vector<uint8_t> cipher2(cipher.begin() + 16, cipher.begin() + 32);
    std::vector<uint8_t> output(16);

    AES_ECB_encrypt_buffer(plain1.data(), key.data(), output.data());
    require_equal("ECB encrypt", output, cipher1);
    AES_ECB_encrypt_buffer(plain2.data(), NULL, output.data());
    require_equal("ECB cached encrypt key", output, cipher2);

    AES_ECB_decrypt_buffer(cipher1.data(), key.data(), output.data());
    require_equal("ECB decrypt", output, plain1);
    AES_ECB_decrypt_buffer(cipher2.data(), NULL, output.data());
    require_equal("ECB cached decrypt key", output, plain2);

    output = plain1;
    AES_ECB_encrypt_buffer(output.data(), key.data(), output.data());
    require_equal("ECB in-place encrypt", output, cipher1);
    AES_ECB_decrypt_buffer(output.data(), key.data(), output.data());
    require_equal("ECB in-place decrypt", output, plain1);

    std::vector<uint8_t> mutable_key = key;
    AES_ECB_encrypt_buffer(plain1.data(), mutable_key.data(), output.data());
    std::memset(mutable_key.data(), 0, mutable_key.size());
    AES_ECB_encrypt_buffer(plain2.data(), NULL, output.data());
    require_equal("ECB cached key owns schedule", output, cipher2);

    AES_ECB_decrypt_buffer(cipher1.data(), key.data(), output.data());
    const std::vector<uint8_t> other_key = alternate_key();
    AES_ECB_encrypt_buffer(plain1.data(), other_key.data(), output.data());
    AES_ECB_decrypt_buffer(cipher2.data(), NULL, output.data());
    require_equal("ECB encrypt/decrypt caches are independent", output, plain2);
}

void test_cbc() {
    const TestVectors& vectors = test_vectors();
    const std::vector<uint8_t> key = from_hex(vectors.key);
    const std::vector<uint8_t> iv = from_hex(kIv);
    const std::vector<uint8_t> plain = from_hex(kPlaintext);
    const std::vector<uint8_t> cipher = from_hex(vectors.cbc);
    if (key.size() != UDP2RAW_AES_KEY_BYTES || plain.size() != 64 ||
        cipher.size() != plain.size() || iv.size() != 16) {
        require_true("CBC test vector sizes", false);
        return;
    }
    std::vector<uint8_t> output(plain.size());

    AES_CBC_encrypt_buffer(output.data(), const_cast<uint8_t*>(plain.data()),
                           static_cast<uint32_t>(plain.size()), key.data(), iv.data());
    require_equal("CBC encrypt", output, cipher);
    AES_CBC_decrypt_buffer(output.data(), const_cast<uint8_t*>(cipher.data()),
                           static_cast<uint32_t>(cipher.size()), key.data(), iv.data());
    require_equal("CBC decrypt", output, plain);

    output = plain;
    AES_CBC_encrypt_buffer(output.data(), output.data(), static_cast<uint32_t>(output.size()),
                           key.data(), iv.data());
    require_equal("CBC in-place encrypt", output, cipher);
    AES_CBC_decrypt_buffer(output.data(), output.data(), static_cast<uint32_t>(output.size()),
                           key.data(), iv.data());
    require_equal("CBC in-place decrypt", output, plain);

    std::vector<uint8_t> mutable_key = key;
    AES_CBC_encrypt_buffer(output.data(), const_cast<uint8_t*>(plain.data()),
                           static_cast<uint32_t>(plain.size()), mutable_key.data(), iv.data());
    std::memset(mutable_key.data(), 0, mutable_key.size());
    AES_CBC_encrypt_buffer(output.data(), const_cast<uint8_t*>(plain.data()),
                           static_cast<uint32_t>(plain.size()), NULL, iv.data());
    require_equal("CBC cached encrypt key", output, cipher);

    AES_CBC_decrypt_buffer(output.data(), const_cast<uint8_t*>(cipher.data()),
                           static_cast<uint32_t>(cipher.size()), key.data(), iv.data());
    const std::vector<uint8_t> other_key = alternate_key();
    AES_CBC_encrypt_buffer(output.data(), const_cast<uint8_t*>(plain.data()),
                           static_cast<uint32_t>(plain.size()), other_key.data(), iv.data());
    AES_CBC_decrypt_buffer(output.data(), const_cast<uint8_t*>(cipher.data()),
                           static_cast<uint32_t>(cipher.size()), NULL, iv.data());
    require_equal("CBC encrypt/decrypt caches are independent", output, plain);

    std::vector<uint8_t> empty;
    AES_CBC_encrypt_buffer(empty.data(), empty.data(), 0, key.data(), iv.data());
    AES_CBC_decrypt_buffer(empty.data(), empty.data(), 0, key.data(), iv.data());
    require_true("CBC zero length", empty.empty());
}

void test_cfb() {
    const TestVectors& vectors = test_vectors();
    const std::vector<uint8_t> key = from_hex(vectors.key);
    const std::vector<uint8_t> iv = from_hex(kIv);
    const std::vector<uint8_t> plain = from_hex(kPlaintext);
    const std::vector<uint8_t> cipher = from_hex(vectors.cfb);
    if (key.size() != UDP2RAW_AES_KEY_BYTES || plain.size() != 64 ||
        cipher.size() != plain.size() || iv.size() != 16) {
        require_true("CFB test vector sizes", false);
        return;
    }
    std::vector<uint8_t> output(plain.size());

    AES_CFB_encrypt_buffer(output.data(), const_cast<uint8_t*>(plain.data()),
                           static_cast<uint32_t>(plain.size()), key.data(), iv.data());
    require_equal("CFB encrypt", output, cipher);
    AES_CFB_decrypt_buffer(output.data(), const_cast<uint8_t*>(cipher.data()),
                           static_cast<uint32_t>(cipher.size()), key.data(), iv.data());
    require_equal("CFB decrypt", output, plain);

    output = plain;
    AES_CFB_encrypt_buffer(output.data(), output.data(), static_cast<uint32_t>(output.size()),
                           key.data(), iv.data());
    require_equal("CFB in-place encrypt", output, cipher);
    AES_CFB_decrypt_buffer(output.data(), output.data(), static_cast<uint32_t>(output.size()),
                           key.data(), iv.data());
    require_equal("CFB in-place decrypt", output, plain);

    std::vector<uint8_t> mutable_key = key;
    AES_CFB_encrypt_buffer(output.data(), const_cast<uint8_t*>(plain.data()),
                           static_cast<uint32_t>(plain.size()), mutable_key.data(), iv.data());
    std::memset(mutable_key.data(), 0, mutable_key.size());
    AES_CFB_encrypt_buffer(output.data(), const_cast<uint8_t*>(plain.data()),
                           static_cast<uint32_t>(plain.size()), NULL, iv.data());
    require_equal("CFB cached encrypt key", output, cipher);

    AES_CFB_decrypt_buffer(output.data(), const_cast<uint8_t*>(cipher.data()),
                           static_cast<uint32_t>(cipher.size()), key.data(), iv.data());
    const std::vector<uint8_t> other_key = alternate_key();
    AES_CFB_encrypt_buffer(output.data(), const_cast<uint8_t*>(plain.data()),
                           static_cast<uint32_t>(plain.size()), other_key.data(), iv.data());
    AES_CFB_decrypt_buffer(output.data(), const_cast<uint8_t*>(cipher.data()),
                           static_cast<uint32_t>(cipher.size()), NULL, iv.data());
    require_equal("CFB encrypt/decrypt caches are independent", output, plain);

    std::vector<uint8_t> empty;
    AES_CFB_encrypt_buffer(empty.data(), empty.data(), 0, key.data(), iv.data());
    AES_CFB_decrypt_buffer(empty.data(), empty.data(), 0, key.data(), iv.data());
    require_true("CFB zero length", empty.empty());
}

uint32_t next_random(uint32_t& state) {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

void fill_random(std::vector<uint8_t>& buffer, uint32_t& state) {
    for (size_t i = 0; i < buffer.size(); ++i) {
        buffer[i] = static_cast<uint8_t>(next_random(state));
    }
}

uint64_t digest_bytes(uint64_t digest, const std::vector<uint8_t>& buffer) {
    for (size_t i = 0; i < buffer.size(); ++i) {
        digest ^= buffer[i];
        digest *= UINT64_C(1099511628211);
    }
    return digest;
}

uint64_t test_differential_corpus() {
    uint32_t random_state = UINT32_C(0x13579bdf);
    uint64_t digest = UINT64_C(1469598103934665603);
    const size_t cfb_lengths[] = {1, 15, 16, 17, 31, 32, 63, 64, 255, 256, 1200, 1408};

    for (size_t length = 16; length <= 2048; length += 16) {
        std::vector<uint8_t> key(UDP2RAW_AES_KEY_BYTES), iv(16), plain(length);
        std::vector<uint8_t> cipher(length), recovered(length), in_place(length);
        fill_random(key, random_state);
        fill_random(iv, random_state);
        fill_random(plain, random_state);
        AES_CBC_encrypt_buffer(cipher.data(), plain.data(), static_cast<uint32_t>(length),
                               key.data(), iv.data());
        AES_CBC_decrypt_buffer(recovered.data(), cipher.data(), static_cast<uint32_t>(length),
                               key.data(), iv.data());
        require_equal("CBC differential round trip", recovered, plain);
        in_place = plain;
        AES_CBC_encrypt_buffer(in_place.data(), in_place.data(), static_cast<uint32_t>(length),
                               NULL, iv.data());
        require_equal("CBC differential in-place encrypt", in_place, cipher);
        AES_CBC_decrypt_buffer(in_place.data(), in_place.data(), static_cast<uint32_t>(length),
                               NULL, iv.data());
        require_equal("CBC differential in-place decrypt", in_place, plain);
        digest = digest_bytes(digest, cipher);
    }

    for (size_t index = 0; index < sizeof(cfb_lengths) / sizeof(cfb_lengths[0]); ++index) {
        const size_t length = cfb_lengths[index];
        std::vector<uint8_t> key(UDP2RAW_AES_KEY_BYTES), iv(16), plain(length);
        std::vector<uint8_t> cipher(length), recovered(length), in_place(length);
        fill_random(key, random_state);
        fill_random(iv, random_state);
        fill_random(plain, random_state);
        AES_CFB_encrypt_buffer(cipher.data(), plain.data(), static_cast<uint32_t>(length),
                               key.data(), iv.data());
        AES_CFB_decrypt_buffer(recovered.data(), cipher.data(), static_cast<uint32_t>(length),
                               key.data(), iv.data());
        require_equal("CFB differential round trip", recovered, plain);
        in_place = plain;
        AES_CFB_encrypt_buffer(in_place.data(), in_place.data(), static_cast<uint32_t>(length),
                               NULL, iv.data());
        require_equal("CFB differential in-place encrypt", in_place, cipher);
        AES_CFB_decrypt_buffer(in_place.data(), in_place.data(), static_cast<uint32_t>(length),
                               NULL, iv.data());
        require_equal("CFB differential in-place decrypt", in_place, plain);
        digest = digest_bytes(digest, cipher);
    }

    return digest;
}

enum BenchmarkMode {
    benchmark_cbc,
    benchmark_cfb,
};

void benchmark(BenchmarkMode mode, size_t size) {
    const size_t total_bytes = 64U * 1024U * 1024U;
    const size_t iterations = total_bytes / size;
    std::vector<uint8_t> key(UDP2RAW_AES_KEY_BYTES, 0x2b);
    std::vector<uint8_t> iv(16, 0x17), input(size, 0x6c), output(size);
    volatile uint8_t sink = 0;

    if (mode == benchmark_cbc) {
        AES_CBC_encrypt_buffer(output.data(), input.data(), static_cast<uint32_t>(size),
                               key.data(), iv.data());
    } else {
        AES_CFB_encrypt_buffer(output.data(), input.data(), static_cast<uint32_t>(size),
                               key.data(), iv.data());
    }
    for (size_t i = 0; i < 256; ++i) {
        if (mode == benchmark_cbc) {
            AES_CBC_encrypt_buffer(output.data(), input.data(), static_cast<uint32_t>(size),
                                   NULL, iv.data());
        } else {
            AES_CFB_encrypt_buffer(output.data(), input.data(), static_cast<uint32_t>(size),
                                   NULL, iv.data());
        }
    }

    const std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        if (mode == benchmark_cbc) {
            AES_CBC_encrypt_buffer(output.data(), input.data(), static_cast<uint32_t>(size),
                                   NULL, iv.data());
        } else {
            AES_CFB_encrypt_buffer(output.data(), input.data(), static_cast<uint32_t>(size),
                                   NULL, iv.data());
        }
        sink ^= output[i % size];
    }
    const std::chrono::duration<double> elapsed = std::chrono::steady_clock::now() - started;
    const double mib_per_second = (static_cast<double>(iterations * size) / (1024.0 * 1024.0)) /
                                  elapsed.count();
    std::printf("benchmark_%s_%zu_mib_per_second=%.2f sink=%u\n",
                mode == benchmark_cbc ? "cbc" : "cfb", size, mib_per_second,
                static_cast<unsigned int>(sink));
}

}  // namespace

int main(int argc, char** argv) {
    bool run_benchmark = false;
    int expected_hw = -1;
    std::string expected_backend;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--benchmark") == 0) {
            run_benchmark = true;
        } else if (std::strncmp(argv[i], "--expect-hw=", 12) == 0) {
            expected_hw = std::atoi(argv[i] + 12);
        } else if (std::strncmp(argv[i], "--expect-backend=", 17) == 0) {
            expected_backend = argv[i] + 17;
        } else {
            std::fprintf(stderr, "unknown argument: %s\n", argv[i]);
            return 2;
        }
    }

    test_dispatch_initialization();
    const int hardware_aes = AES_support_hwaccel();
    const char* backend = AES_backend_name();
    if (expected_hw != -1) {
        require_true("hardware AES expectation", hardware_aes == expected_hw);
    }
    if (!expected_backend.empty()) {
        require_true("backend expectation", expected_backend == backend);
    }

    test_ecb();
    test_cbc();
    test_cfb();
    const uint64_t corpus_digest = test_differential_corpus();
#if UDP2RAW_AES_KEY_BITS == 128
    require_true("AES-128 corpus digest",
                 corpus_digest == UINT64_C(0xbc77f007f1106656));
#endif

    std::printf("hardware_aes=%d\n", hardware_aes);
    std::printf("backend=%s\n", backend);
    std::printf("aes_key_bits=%d\n", UDP2RAW_AES_KEY_BITS);
    std::printf("corpus_digest=%016llx\n",
                static_cast<unsigned long long>(corpus_digest));
    std::printf("aes_backend_tests=%s\n", failures == 0 ? "passed" : "failed");

    if (run_benchmark && failures == 0) {
        const size_t sizes[] = {64, 256, 1024, 1408};
        for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
            benchmark(benchmark_cbc, sizes[i]);
            benchmark(benchmark_cfb, sizes[i]);
        }
    }

    return failures == 0 ? 0 : 1;
}
