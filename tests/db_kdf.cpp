#include <catch2/catch_all.hpp>
#include "DatabaseManager.hpp"
#include <filesystem>
#include <vector>
#include <cstdint>
#include <string>

TEST_CASE("DB: store/load kdf_salt", "[db][kdf]") {
    const std::string testDb = "tmp_test_kdf.sqlite";
    std::filesystem::remove(testDb);

    DatabaseManager db(testDb);
    REQUIRE_NOTHROW(db.init());

    // Initially absent
    auto before = db.loadKdfSalt();
    REQUIRE_FALSE(before.has_value());

    // Store dummy salt
    std::vector<std::uint8_t> salt(16, 0x5A);
    REQUIRE_NOTHROW(db.storeKdfSalt(salt));

    // Load back
    auto after = db.loadKdfSalt();
    REQUIRE(after.has_value());
    REQUIRE(after->size() == 16);
    REQUIRE(*after == salt);

    // Upsert with different bytes
    std::vector<std::uint8_t> salt2(16, 0xA5);
    REQUIRE_NOTHROW(db.storeKdfSalt(salt2));

    auto after2 = db.loadKdfSalt();
    REQUIRE(after2.has_value());
    REQUIRE(*after2 == salt2);
}
