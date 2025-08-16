#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>

// Forward-declare sqlite3 so consumers of this header don't need sqlite3.h
struct sqlite3;

// Full credential row used by most CRUD APIs
struct Credential {
    int id;
    std::string service;
    std::string username;
    std::vector<std::uint8_t> enc_password; // ciphertext (+tag if GCM)
    std::vector<std::uint8_t> iv;           // per-row IV
    std::string notes;
    std::string created_at;                 // ISO-8601 (UTC)
};

// Lightweight row for bulk operations (e.g., change-master re-encryption)
struct CredentialRow {
    int id;
    std::string service;
    std::string username;
    std::string created_at;
    std::vector<std::uint8_t> enc_password;
    std::vector<std::uint8_t> iv;
    std::string notes; // include notes so we can preserve them on update
};

class DatabaseManager {
public:
    explicit DatabaseManager(const std::string& dbPath);
    ~DatabaseManager();

    // Create tables if not present
    void init();

    // ---- Master auth (id=1)
    void storeMaster(const std::vector<std::uint8_t>& salt,
                     const std::vector<std::uint8_t>& hash);
    // returns {salt, hash} or nullopt
    std::optional<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>>
    loadMaster() const;

    // ---- App settings (KDF salt at id=1)
    void storeKdfSalt(const std::vector<std::uint8_t>& kdfSalt);
    std::optional<std::vector<std::uint8_t>> loadKdfSalt() const;

    // ---- Credentials CRUD
    int addCredential(const std::string& service,
                      const std::string& username,
                      const std::vector<std::uint8_t>& encPassword,
                      const std::vector<std::uint8_t>& iv,
                      const std::string& notes);

    std::optional<Credential> getCredentialById(int id) const;
    std::vector<Credential>   searchByService(const std::string& query) const;
    void updateCredential(int id,
                          const std::string& newUsername,
                          const std::vector<std::uint8_t>& newEncPassword,
                          const std::vector<std::uint8_t>& newIv,
                          const std::string& newNotes);
    void deleteCredential(int id);

    // ---- Bulk / maintenance & transactions
    std::vector<CredentialRow> getAllCredentials() const;
    void beginTransaction();
    void commit();
    void rollback();

    // ---- Test-only helper
    void test_updateCreatedAt(int id, const std::string& createdAt);

private:
    std::string m_dbPath;
    sqlite3*    m_db = nullptr; // persistent DB connection

    // helper to run raw SQL without parameters on m_db
    void exec(const std::string& sql) const;
};
