// tests/auth_gate.cpp
#include <catch2/catch_all.hpp>
#include "AuthManager.hpp"

TEST_CASE("AuthManager Argon2 verify", "[auth]") {
    AuthManager auth;
    auto record = auth.createMasterRecord("correct horse battery staple");

    SECTION("Correct password verifies") {
        REQUIRE(auth.verifyMasterPassword("correct horse battery staple", record));
    }
    SECTION("Wrong password fails") {
        REQUIRE_FALSE(auth.verifyMasterPassword("Tr0ub4dor&3", record));
    }
}
