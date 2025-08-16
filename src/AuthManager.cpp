#include "AuthManager.hpp"

#include <openssl/rand.h>   // RAND_bytes
#include <argon2.h>         // Argon2id
#include <stdexcept>

StoredAuth AuthManager::createMasterRecord(const std::string& masterPassword) const {
    // 1) Generate random 16-byte salt
    std::vector<std::uint8_t> salt(SALT_LEN);
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed for auth_salt");
    }

    // 2) Argon2id hash (32 bytes)
    std::vector<std::uint8_t> hash(HASH_LEN);
    int rc = argon2id_hash_raw(
        T_COST,                // t (iterations)
        M_COST_KiB,            // m (KiB)
        PARALLELISM,           // p
        masterPassword.data(),
        masterPassword.size(),
        salt.data(),           // salt
        salt.size(),
        hash.data(),           // out
        hash.size()
    );
    if (rc != ARGON2_OK) {
        throw std::runtime_error(std::string("argon2id_hash_raw failed: ") + argon2_error_message(rc));
    }

    return StoredAuth{ std::move(salt), std::move(hash) };
}

bool AuthManager::verifyMasterPassword(const std::string& masterPassword,
                                       const StoredAuth& stored) const {
    // Recompute Argon2id with stored salt; compare in constant time
    if (stored.salt.size() != SALT_LEN || stored.hash.size() != HASH_LEN) {
        return false;
    }

    std::vector<std::uint8_t> recomputed(HASH_LEN);
    int rc = argon2id_hash_raw(
        T_COST,
        M_COST_KiB,
        PARALLELISM,
        masterPassword.data(),
        masterPassword.size(),
        const_cast<std::uint8_t*>(stored.salt.data()), // argon2 API takes non-const
        stored.salt.size(),
        recomputed.data(),
        recomputed.size()
    );
    if (rc != ARGON2_OK) {
        return false;
    }

    return constTimeEqual(recomputed, stored.hash);
}

bool AuthManager::constTimeEqual(const std::vector<std::uint8_t>& a,
                                 const std::vector<std::uint8_t>& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}
