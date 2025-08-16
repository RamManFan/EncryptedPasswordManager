#include "EncryptionManager.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <argon2.h>
#include <stdexcept>
#include <cstring>
#include <memory>

std::vector<std::uint8_t> EncryptionManager::deriveKey(
    const std::string& masterPassword,
    const std::vector<std::uint8_t>& kdfSalt
) {
    if (kdfSalt.size() != 16) {
        throw std::invalid_argument("deriveKey: kdfSalt must be 16 bytes");
    }
    std::vector<std::uint8_t> key(KEY_LEN);

    int rc = argon2id_hash_raw(
        T_COST,
        M_COST_KiB,
        PARALLELISM,
        masterPassword.data(), masterPassword.size(),
        const_cast<std::uint8_t*>(kdfSalt.data()), kdfSalt.size(),
        key.data(), key.size()
    );
    if (rc != ARGON2_OK) {
        throw std::runtime_error(std::string("argon2id_hash_raw failed: ")
                                 + argon2_error_message(rc));
    }
    return key;
}

EncryptionManager::EncryptionManager(const std::vector<std::uint8_t>& key)
: m_key(key)
{
    if (m_key.size() != KEY_LEN) {
        throw std::invalid_argument("EncryptionManager: key must be 32 bytes");
    }
}

EncryptionManager::EncResult EncryptionManager::encrypt(
    const std::vector<std::uint8_t>& plaintext,
    const std::vector<std::uint8_t>& aad
) const {
    EncResult out;
    out.iv.resize(IV_LEN);
    if (RAND_bytes(out.iv.data(), static_cast<int>(out.iv.size())) != 1) {
        throw std::runtime_error("encrypt: RAND_bytes(IV) failed");
    }

    // allocate: ciphertext same size as plaintext + 16B tag (final resize after Final)
    out.encAndTag.resize(plaintext.size() + TAG_LEN);

    // ctx with RAII deleter
    EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new();
    if (!raw) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(raw, &EVP_CIPHER_CTX_free);

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EncryptInit cipher failed");
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) != 1)
        throw std::runtime_error("SET_IVLEN failed");
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, m_key.data(), out.iv.data()) != 1)
        throw std::runtime_error("EncryptInit key/iv failed");

    int len = 0;
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
            throw std::runtime_error("EncryptUpdate AAD failed");
    }

    int outLen1 = 0;
    if (EVP_EncryptUpdate(ctx.get(),
                          out.encAndTag.data(), &outLen1,
                          plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        throw std::runtime_error("EncryptUpdate data failed");
    }

    int outLen2 = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), out.encAndTag.data() + outLen1, &outLen2) != 1) {
        throw std::runtime_error("EncryptFinal failed");
    }

    std::uint8_t tag[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1)
        throw std::runtime_error("GET_TAG failed");

    out.encAndTag.resize(static_cast<std::size_t>(outLen1 + outLen2) + TAG_LEN);
    std::memcpy(out.encAndTag.data() + (out.encAndTag.size() - TAG_LEN), tag, TAG_LEN);

    return out;
}

std::vector<std::uint8_t> EncryptionManager::decrypt(
    const std::vector<std::uint8_t>& iv,
    const std::vector<std::uint8_t>& encAndTag,
    const std::vector<std::uint8_t>& aad
) const {
    if (iv.size() != IV_LEN) {
        throw std::invalid_argument("decrypt: IV must be 12 bytes");
    }
    if (encAndTag.size() < TAG_LEN) {
        throw std::invalid_argument("decrypt: input too short");
    }

    const std::size_t cLen = encAndTag.size() - TAG_LEN;
    const std::uint8_t* ciphertext = encAndTag.data();
    const std::uint8_t* tag        = encAndTag.data() + cLen;

    std::vector<std::uint8_t> plaintext(cLen);

    EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new();
    if (!raw) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(raw, &EVP_CIPHER_CTX_free);

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("DecryptInit cipher failed");
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) != 1)
        throw std::runtime_error("SET_IVLEN failed");
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, m_key.data(), iv.data()) != 1)
        throw std::runtime_error("DecryptInit key/iv failed");

    int len = 0;
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
            throw std::runtime_error("DecryptUpdate AAD failed");
    }

    int pLen1 = 0;
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &pLen1, ciphertext, static_cast<int>(cLen)) != 1)
        throw std::runtime_error("DecryptUpdate data failed");

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_LEN, const_cast<std::uint8_t*>(tag)) != 1)
        throw std::runtime_error("SET_TAG failed");

    int pLen2 = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + pLen1, &pLen2) != 1) {
        throw std::runtime_error("GCM tag verification failed");
    }

    plaintext.resize(static_cast<std::size_t>(pLen1 + pLen2));
    return plaintext;
}
