// tests/db_master.cpp
#include <catch2/catch_all.hpp>
#include "DatabaseManager.hpp"

#include <filesystem>
#include <vector>
#include <cstdint>
#include <string>

TEST_CASE("DB: init() creates schema; master record upsert/load works", "[db][master]") {
    // 1) Use a throwaway DB file so we don't touch data/epm.sqlite
    const std::string testDb = "tmp_test_master.sqlite";
    std::filesystem::remove(testDb);

    // 2) Init schema
    DatabaseManager db(testDb);
    REQUIRE_NOTHROW(db.init());

    // 3) Before storing, loadMaster() should be empty
    auto before = db.loadMaster();
    REQUIRE_FALSE(before.has_value());

    // 4) Store a known salt+hash and read it back
    std::vector<std::uint8_t> salt = {0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08,
                                      0x09,0x0A,0x0B,0x0C, 0x0D,0x0E,0x0F,0x10};
    std::vector<std::uint8_t> hash(32, 0xAB); // 32 bytes of 0xAB (dummy)

    REQUIRE_NOTHROW(db.storeMaster(salt, hash));

    auto rec = db.loadMaster();
    REQUIRE(rec.has_value());
    REQUIRE(rec->first  == salt); // rec->first  is salt
    REQUIRE(rec->second == hash); // rec->second is hash

    // 5) Upsert behavior: store new values and ensure they overwrite the old
    std::vector<std::uint8_t> salt2(16, 0x11);
    std::vector<std::uint8_t> hash2(32, 0x22);

    REQUIRE_NOTHROW(db.storeMaster(salt2, hash2));

    auto rec2 = db.loadMaster();
    REQUIRE(rec2.has_value());
    REQUIRE(rec2->first  == salt2);
    REQUIRE(rec2->second == hash2);

    // 6) Clean up the temp file (optional; safe to leave too)
    //std::filesystem::remove(testDb);
}
