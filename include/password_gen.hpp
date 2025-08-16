#pragma once
#include <string>
#include <vector>
#include <stdexcept>
#include <openssl/rand.h>

inline std::string generate_password(std::size_t length,
                                     bool useUpper=true,
                                     bool useLower=true,
                                     bool useDigits=true,
                                     bool useSymbols=true)
{
    const std::string U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string L = "abcdefghijklmnopqrstuvwxyz";
    const std::string D = "0123456789";
    const std::string S = "!@#$%^&*()-_=+[]{};:,.?/";

    std::string alphabet;
    if (useUpper)  alphabet += U;
    if (useLower)  alphabet += L;
    if (useDigits) alphabet += D;
    if (useSymbols)alphabet += S;
    if (alphabet.empty()) throw std::invalid_argument("Empty alphabet");

    if (length == 0) return {};

    std::string out(length, '\0');

    // Use rejection sampling to avoid modulo bias.
    const unsigned int maxByte = 255;
    const unsigned int bound   = (maxByte / alphabet.size()) * alphabet.size();

    std::vector<unsigned char> buf(length * 2); // plenty
    std::size_t produced = 0;
    while (produced < length) {
        if (RAND_bytes(buf.data(), static_cast<int>(buf.size())) != 1) {
            throw std::runtime_error("RAND_bytes failed in generate_password");
        }
        for (unsigned char b : buf) {
            if (b >= bound) continue;
            out[produced++] = alphabet[b % alphabet.size()];
            if (produced == length) break;
        }
    }
    return out;
}
