#include <catch2/catch_all.hpp>
#include "EncryptionManager.hpp"
#include <cstring>

static std::vector<std::uint8_t> toBytes(const char* s) {
    return std::vector<std::uint8_t>(reinterpret_cast<const std::uint8_t*>(s),
                                     reinterpret_cast<const std::uint8_t*>(s) + std::strlen(s));
}

TEST_CASE("AES-GCM: round-trip succeeds; tamper fails", "[crypto]") {
    // In the app, kdf_salt comes from DB (random 16B). For test use a fixed salt.
    std::vector<std::uint8_t> kdfSalt(16, 0x11);
    std::string master = "correct horse battery staple";

    auto key = EncryptionManager::deriveKey(master, kdfSalt);
    REQUIRE(key.size() == 32);

    EncryptionManager enc(key);

    auto pt  = toBytes("secret-password-123!");
    auto aad = toBytes("row-metadata");

    auto encRes = enc.encrypt(pt, aad);
    REQUIRE(encRes.iv.size() == 12);
    REQUIRE(encRes.encAndTag.size() >= 16);

    // Good decrypt
    auto dec = enc.decrypt(encRes.iv, encRes.encAndTag, aad);
    REQUIRE(dec == pt);

    // Tamper one byte -> tag verify must fail
    auto bad = encRes.encAndTag;
    if (bad.size() > 16) {
        bad[0] ^= 0x01; // flip a bit in ciphertext
        REQUIRE_THROWS_WITH(
            enc.decrypt(encRes.iv, bad, aad),
            "GCM tag verification failed"
        );
    }
}
