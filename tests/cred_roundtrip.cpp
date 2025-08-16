#include <catch2/catch_all.hpp>

#include "DatabaseManager.hpp"
#include "EncryptionManager.hpp"

#include <filesystem>
#include <string>
#include <vector>
#include <cstdint>

// tiny helper
static std::vector<std::uint8_t> toBytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

TEST_CASE("Credentials: AES-GCM round-trip with stable AAD", "[db][crypto][cred]") {
    const std::string dbPath = "tmp_e2e.sqlite";

    // Do all DB work in a local scope so the file handle is closed
    // before we attempt cleanup at the end (important on Windows).
    {
        // Clean start
        std::error_code ec;
        std::filesystem::remove(dbPath, ec);

        DatabaseManager db(dbPath);
        db.init();

        // Fixed 16B KDF salt and password → deterministic 32B key
        std::vector<std::uint8_t> kdfSalt(16, 0x11);
        auto key = EncryptionManager::deriveKey("pw-for-test", kdfSalt);
        REQUIRE(key.size() == 32);
        EncryptionManager enc(key);

        // Test data
        const std::string service   = "github";
        const std::string username  = "octocat";
        const std::string notes     = "personal account";
        const std::string secret    = "s3cr3t-🐙-token";

        // We choose a *known* created_at to build AAD (same format as DB uses)
        const std::string created_at = "2025-01-01T00:00:00Z";

        // AAD = service \n username \n created_at
        const std::string aad_str = service + "\n" + username + "\n" + created_at;
        const auto aad = toBytes(aad_str);

        // Encrypt
        auto encRes = enc.encrypt(toBytes(secret), aad);
        REQUIRE(encRes.iv.size() == 12);
        REQUIRE(encRes.encAndTag.size() >= 16);

        // Insert row (DB will stamp its created_at; we overwrite to our chosen test value)
        int id = db.addCredential(service, username, encRes.encAndTag, encRes.iv, notes);
        REQUIRE(id > 0);

        db.test_updateCreatedAt(id, created_at);

        // Fetch & decrypt -> must round-trip
        auto row = db.getCredentialById(id);
        REQUIRE(row.has_value());
        REQUIRE(row->service    == service);
        REQUIRE(row->username   == username);
        REQUIRE(row->created_at == created_at);

        auto pt = enc.decrypt(row->iv, row->enc_password, aad);
        std::string recovered(pt.begin(), pt.end());
        REQUIRE(recovered == secret);

        // Wrong AAD must fail (flip username in AAD)
        const auto wrongAad = toBytes(service + "\nWRONG\n" + created_at);
        REQUIRE_THROWS_AS(enc.decrypt(row->iv, row->enc_password, wrongAad), std::runtime_error);

        // ----- Update flow: change username and secret -----
        const std::string newUser   = "octoPRO";
        const std::string newSecret = "NEW-🐙-token";

        // New AAD uses (service, newUser, same created_at)
        const std::string aad2_str = service + "\n" + newUser + "\n" + created_at;
        const auto aad2 = toBytes(aad2_str);

        auto encRes2 = enc.encrypt(toBytes(newSecret), aad2);
        db.updateCredential(id, newUser, encRes2.encAndTag, encRes2.iv, row->notes);

        auto row2 = db.getCredentialById(id);
        REQUIRE(row2.has_value());
        REQUIRE(row2->username   == newUser);
        REQUIRE(row2->created_at == created_at); // unchanged

        auto pt2 = enc.decrypt(row2->iv, row2->enc_password, aad2);
        std::string recovered2(pt2.begin(), pt2.end());
        REQUIRE(recovered2 == newSecret);

        // Ensure old AAD doesn’t work anymore after username change
        REQUIRE_THROWS_AS(enc.decrypt(row2->iv, row2->enc_password, aad), std::runtime_error);
    }

    // Cleanup after DB handle is closed
    std::error_code ec2;
    std::filesystem::remove(dbPath, ec2);
}
