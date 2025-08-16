#pragma once
#include <vector>
#include <string>
#include <cstdint>

struct StoredAuth {
    std::vector<std::uint8_t> salt; // 16 bytes
    std::vector<std::uint8_t> hash; // 32 bytes (Argon2id output)
};

class AuthManager {
public:
    // Create new master record from plaintext password:
    // - generates 16B salt
    // - Argon2id with t=3, m≈64 MiB, p=1 -> 32B hash
    StoredAuth createMasterRecord(const std::string& masterPassword) const;

    // Verify password against stored {salt, hash}
    bool verifyMasterPassword(const std::string& masterPassword,
                              const StoredAuth& stored) const;

private:
    static bool constTimeEqual(const std::vector<std::uint8_t>& a,
                               const std::vector<std::uint8_t>& b);

    static constexpr std::size_t SALT_LEN = 16;
    static constexpr std::size_t HASH_LEN = 32;

    // Argon2id params
    static constexpr uint32_t T_COST = 3;        // iterations
    static constexpr uint32_t M_COST_KiB = 64 * 1024; // ~64 MiB
    static constexpr uint32_t PARALLELISM = 1;
};
