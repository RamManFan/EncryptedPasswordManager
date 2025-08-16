#pragma once
#include <cstdint>
#include <vector>
#include <string>

// Handles key derivation (Argon2id) and AES-256-GCM encrypt/decrypt.
// Keep the derived key only in RAM for the session.
class EncryptionManager {
public:
    // Derive a 32-byte key from master password and 16-byte salt (Argon2id).
    static std::vector<std::uint8_t> deriveKey(
        const std::string& masterPassword,
        const std::vector<std::uint8_t>& kdfSalt
    );

    // Construct with 32-byte key (K_enc).
    explicit EncryptionManager(const std::vector<std::uint8_t>& key);

    struct EncResult {
        std::vector<std::uint8_t> iv;         // 12-byte random IV
        std::vector<std::uint8_t> encAndTag;  // ciphertext || 16-byte tag
    };

    // Optional AAD lets you bind extra metadata; can be empty.
    EncResult encrypt(const std::vector<std::uint8_t>& plaintext,
                      const std::vector<std::uint8_t>& aad = {}) const;

    // Throws std::runtime_error on tag verification failure or API error.
    std::vector<std::uint8_t> decrypt(const std::vector<std::uint8_t>& iv,
                                      const std::vector<std::uint8_t>& encAndTag,
                                      const std::vector<std::uint8_t>& aad = {}) const;

private:
    std::vector<std::uint8_t> m_key;

    static constexpr std::size_t KEY_LEN = 32;
    static constexpr std::size_t IV_LEN  = 12;
    static constexpr std::size_t TAG_LEN = 16;

    static constexpr uint32_t T_COST = 3;               // iterations
    static constexpr uint32_t M_COST_KiB = 64 * 1024;   // memory (~64 MiB)
    static constexpr uint32_t PARALLELISM = 1;          // lanes
};
