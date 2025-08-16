// src/DatabaseManager.cpp
#include "DatabaseManager.hpp"

#include <sqlite3.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <memory>     // std::unique_ptr
#include <optional>   // std::optional
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cstdint>

// Helper: RAII closer for sqlite3_stmt* + small helpers
namespace {
    struct StmtCloser {
        void operator()(sqlite3_stmt* stmt) const {
            if (stmt) sqlite3_finalize(stmt);
        }
    };

    // UTC now in ISO-8601 "YYYY-MM-DDTHH:MM:SSZ"
    std::string now_utc_iso8601() {
        using namespace std::chrono;
        auto now  = system_clock::now();
        auto secs = time_point_cast<seconds>(now);
        std::time_t t = system_clock::to_time_t(secs);
        std::tm tm{};
    #if defined(_WIN32)
        gmtime_s(&tm, &t);
    #else
        gmtime_r(&t, &tm);
    #endif
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
        return oss.str();
    }

    // Escape %, _ and \ for use in a LIKE ... ESCAPE '\' clause
    std::string escape_like(const std::string& in) {
        std::string out;
        out.reserve(in.size() * 2);
        for (char ch : in) {
            if (ch == '%' || ch == '_' || ch == '\\') out.push_back('\\');
            out.push_back(ch);
        }
        return out;
    }

    // Null-safe read of TEXT columns
    inline std::string read_text_nullable(sqlite3_stmt* st, int col) {
        const unsigned char* p = sqlite3_column_text(st, col);
        return p ? reinterpret_cast<const char*>(p) : std::string{};
    }
}

// ---- Persistent-connection ctor/dtor ----
DatabaseManager::DatabaseManager(const std::string& dbPath)
    : m_dbPath(dbPath), m_db(nullptr)
{
    int rc = sqlite3_open_v2(
        m_dbPath.c_str(),
        &m_db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
        nullptr
    );
    if (rc != SQLITE_OK || !m_db) {
        std::string msg = m_db ? sqlite3_errmsg(m_db) : "unknown";
        if (m_db) sqlite3_close(m_db);
        m_db = nullptr;
        throw std::runtime_error("sqlite3_open_v2 failed: " + msg);
    }

    // Recommended pragmas (safe no-ops if unsupported)
    exec("PRAGMA foreign_keys = ON;");
    // exec("PRAGMA journal_mode = WAL;");
}

DatabaseManager::~DatabaseManager() {
    if (m_db) {
        sqlite3_close(m_db);
        m_db = nullptr;
    }
}

// Run raw SQL (no parameters) on the same connection
void DatabaseManager::exec(const std::string& sql) const {
    char* errMsg = nullptr;
    int rc = sqlite3_exec(m_db, sql.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::string msg = errMsg ? errMsg : "unknown";
        sqlite3_free(errMsg);
        throw std::runtime_error("sqlite3_exec failed: " + msg);
    }
}

// Create tables & index if missing (your schema)
void DatabaseManager::init() {
    static const char* kSchema = R"SQL(
CREATE TABLE IF NOT EXISTS master_auth (
  id   INTEGER PRIMARY KEY CHECK (id = 1),
  salt BLOB NOT NULL,
  hash BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS app_settings (
  id       INTEGER PRIMARY KEY CHECK (id = 1),
  kdf_salt BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  service            TEXT NOT NULL,
  username           TEXT NOT NULL,
  encrypted_password BLOB NOT NULL,
  iv                 BLOB NOT NULL,
  notes              TEXT DEFAULT '',
  created_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credentials_service ON credentials(service);
CREATE INDEX IF NOT EXISTS idx_credentials_service_user ON credentials(service, username);
)SQL";

    exec(kSchema);
}

// ---- Master auth (id=1)

void DatabaseManager::storeMaster(const std::vector<std::uint8_t>& salt,
                                  const std::vector<std::uint8_t>& hash) {
    const char* sql =
        "INSERT INTO master_auth (id, salt, hash) VALUES (1, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET salt=excluded.salt, hash=excluded.hash;";

    sqlite3_stmt* stmtRaw = nullptr;
    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(std::string("sqlite3_prepare_v2(storeMaster): ")
                                 + sqlite3_errmsg(m_db));
    }
    std::unique_ptr<sqlite3_stmt, StmtCloser> stmt(stmtRaw);

    rc = sqlite3_bind_blob(stmt.get(), 1, salt.data(), static_cast<int>(salt.size()), SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) throw std::runtime_error(std::string("bind salt: ") + sqlite3_errmsg(m_db));

    rc = sqlite3_bind_blob(stmt.get(), 2, hash.data(), static_cast<int>(hash.size()), SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) throw std::runtime_error(std::string("bind hash: ") + sqlite3_errmsg(m_db));

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        throw std::runtime_error(std::string("step storeMaster: ") + sqlite3_errmsg(m_db));
    }
}

std::optional<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>>
DatabaseManager::loadMaster() const {
    const char* sql = "SELECT salt, hash FROM master_auth WHERE id = 1;";
    sqlite3_stmt* stmtRaw = nullptr;
    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(std::string("sqlite3_prepare_v2(loadMaster): ")
                                 + sqlite3_errmsg(m_db));
    }
    std::unique_ptr<sqlite3_stmt, StmtCloser> stmt(stmtRaw);

    rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        const void* saltPtr = sqlite3_column_blob(stmt.get(), 0);
        int saltBytes = sqlite3_column_bytes(stmt.get(), 0);
        const void* hashPtr = sqlite3_column_blob(stmt.get(), 1);
        int hashBytes = sqlite3_column_bytes(stmt.get(), 1);

        std::vector<std::uint8_t> saltVec, hashVec;
        if (saltPtr && saltBytes > 0) {
            const auto* b = static_cast<const std::uint8_t*>(saltPtr);
            saltVec.assign(b, b + saltBytes);
        }
        if (hashPtr && hashBytes > 0) {
            const auto* b = static_cast<const std::uint8_t*>(hashPtr);
            hashVec.assign(b, b + hashBytes);
        }
        return std::make_optional(std::make_pair(std::move(saltVec), std::move(hashVec)));
    } else if (rc == SQLITE_DONE) {
        return std::nullopt;
    } else {
        throw std::runtime_error(std::string("sqlite3_step(loadMaster): ") + sqlite3_errmsg(m_db));
    }
}

// ---- App settings (KDF salt at id=1)

void DatabaseManager::storeKdfSalt(const std::vector<std::uint8_t>& kdfSalt) {
    if (kdfSalt.empty()) {
        throw std::invalid_argument("storeKdfSalt: kdfSalt must not be empty");
    }

    const char* sql =
        "INSERT INTO app_settings (id, kdf_salt) VALUES (1, ?) "
        "ON CONFLICT(id) DO UPDATE SET kdf_salt=excluded.kdf_salt;";

    sqlite3_stmt* stmtRaw = nullptr;
    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(std::string("sqlite3_prepare_v2(storeKdfSalt): ")
                                 + sqlite3_errmsg(m_db));
    }
    std::unique_ptr<sqlite3_stmt, StmtCloser> stmt(stmtRaw);

    rc = sqlite3_bind_blob(stmt.get(), 1, kdfSalt.data(),
                           static_cast<int>(kdfSalt.size()), SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(std::string("bind kdf_salt: ") + sqlite3_errmsg(m_db));
    }

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        throw std::runtime_error(std::string("step storeKdfSalt: ") + sqlite3_errmsg(m_db));
    }
}

std::optional<std::vector<std::uint8_t>> DatabaseManager::loadKdfSalt() const {
    const char* sql = "SELECT kdf_salt FROM app_settings WHERE id = 1;";
    sqlite3_stmt* stmtRaw = nullptr;
    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(std::string("sqlite3_prepare_v2(loadKdfSalt): ")
                                 + sqlite3_errmsg(m_db));
    }
    std::unique_ptr<sqlite3_stmt, StmtCloser> stmt(stmtRaw);

    rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        const void* ptr = sqlite3_column_blob(stmt.get(), 0);
        int nbytes = sqlite3_column_bytes(stmt.get(), 0);
        std::vector<std::uint8_t> salt;
        if (ptr && nbytes > 0) {
            const auto* b = static_cast<const std::uint8_t*>(ptr);
            salt.assign(b, b + nbytes);
        }
        return salt;
    } else if (rc == SQLITE_DONE) {
        return std::nullopt;
    } else {
        throw std::runtime_error(std::string("sqlite3_step(loadKdfSalt): ") + sqlite3_errmsg(m_db));
    }
}

// --------- Encrypted credentials CRUD ---------

int DatabaseManager::addCredential(const std::string& service,
                                   const std::string& username,
                                   const std::vector<std::uint8_t>& encPassword,
                                   const std::vector<std::uint8_t>& iv,
                                   const std::string& notes)
{
    const char* sql = R"SQL(
        INSERT INTO credentials(service, username, encrypted_password, iv, notes, created_at)
        VALUES(?, ?, ?, ?, ?, ?);
    )SQL";

    sqlite3_stmt* stmtRaw = nullptr;
    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(std::string("prepare insert credential failed: ")
                                 + sqlite3_errmsg(m_db));
    }
    std::unique_ptr<sqlite3_stmt, StmtCloser> stmt(stmtRaw);

    auto bind_ok = [&](int code, const char* what) {
        if (code != SQLITE_OK) {
            throw std::runtime_error(std::string(what) + ": " + sqlite3_errmsg(m_db));
        }
    };

    bind_ok(sqlite3_bind_text(stmt.get(), 1, service.c_str(),  -1, SQLITE_TRANSIENT),  "bind service");
    bind_ok(sqlite3_bind_text(stmt.get(), 2, username.c_str(), -1, SQLITE_TRANSIENT),  "bind username");
    bind_ok(sqlite3_bind_blob(stmt.get(), 3, encPassword.data(),
                              static_cast<int>(encPassword.size()), SQLITE_TRANSIENT), "bind encPassword");
    bind_ok(sqlite3_bind_blob(stmt.get(), 4, iv.data(),
                              static_cast<int>(iv.size()),          SQLITE_TRANSIENT), "bind iv");
    bind_ok(sqlite3_bind_text(stmt.get(), 5, notes.c_str(),     -1, SQLITE_TRANSIENT), "bind notes");

    const std::string ts = now_utc_iso8601();
    bind_ok(sqlite3_bind_text(stmt.get(), 6, ts.c_str(), -1, SQLITE_TRANSIENT), "bind created_at");

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        throw std::runtime_error(std::string("insert credential step failed: ")
                                 + sqlite3_errmsg(m_db));
    }

    int id = static_cast<int>(sqlite3_last_insert_rowid(m_db));
    return id;
}

std::optional<Credential> DatabaseManager::getCredentialById(int id) const {
    const char* sql = R"SQL(
        SELECT id, service, username, encrypted_password, iv, notes, created_at
        FROM credentials WHERE id = ?;
    )SQL";

    sqlite3_stmt* stmtRaw = nullptr;
    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(std::string("prepare getCredentialById failed: ")
                                 + sqlite3_errmsg(m_db));
    }
    std::unique_ptr<sqlite3_stmt, StmtCloser> stmt(stmtRaw);

    rc = sqlite3_bind_int(stmt.get(), 1, id);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(std::string("bind id failed: ") + sqlite3_errmsg(m_db));
    }

    rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        Credential c{};
        c.id       = sqlite3_column_int(stmt.get(), 0);
        c.service  = read_text_nullable(stmt.get(), 1);
        c.username = read_text_nullable(stmt.get(), 2);

        const void* encPtr = sqlite3_column_blob(stmt.get(), 3);
        int encLen = sqlite3_column_bytes(stmt.get(), 3);
        if (encPtr && encLen > 0) {
            const auto* p = static_cast<const std::uint8_t*>(encPtr);
            c.enc_password.assign(p, p + encLen);
        }

        const void* ivPtr = sqlite3_column_blob(stmt.get(), 4);
        int ivLen = sqlite3_column_bytes(stmt.get(), 4);
        if (ivPtr && ivLen > 0) {
            const auto* p = static_cast<const std::uint8_t*>(ivPtr);
            c.iv.assign(p, p + ivLen);
        }

        c.notes      = read_text_nullable(stmt.get(), 5);
        c.created_at = read_text_nullable(stmt.get(), 6);

        return c;
    } else if (rc == SQLITE_DONE) {
        return std::nullopt;
    } else {
        throw std::runtime_error(std::string("step getCredentialById failed: ")
                                 + sqlite3_errmsg(m_db));
    }
}

std::vector<Credential> DatabaseManager::searchByService(const std::string& query) const {
    const char* sql = R"SQL(
        SELECT id, service, username, encrypted_password, iv, notes, created_at
        FROM credentials WHERE service LIKE ? ESCAPE '\'
        ORDER BY created_at DESC, id DESC;
    )SQL";

    sqlite3_stmt* stmtRaw = nullptr;
    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(std::string("prepare searchByService failed: ")
                                 + sqlite3_errmsg(m_db));
    }
    std::unique_ptr<sqlite3_stmt, StmtCloser> stmt(stmtRaw);

    std::string pattern = "%" + escape_like(query) + "%";
    rc = sqlite3_bind_text(stmt.get(), 1, pattern.c_str(), -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(std::string("bind pattern failed: ") + sqlite3_errmsg(m_db));
    }

    std::vector<Credential> out;
    while ((rc = sqlite3_step(stmt.get())) == SQLITE_ROW) {
        Credential c{};
        c.id       = sqlite3_column_int(stmt.get(), 0);
        c.service  = read_text_nullable(stmt.get(), 1);
        c.username = read_text_nullable(stmt.get(), 2);

        const void* encPtr = sqlite3_column_blob(stmt.get(), 3);
        int encLen = sqlite3_column_bytes(stmt.get(), 3);
        if (encPtr && encLen > 0) {
            const auto* p = static_cast<const std::uint8_t*>(encPtr);
            c.enc_password.assign(p, p + encLen);
        }

        const void* ivPtr = sqlite3_column_blob(stmt.get(), 4);
        int ivLen = sqlite3_column_bytes(stmt.get(), 4);
        if (ivPtr && ivLen > 0) {
            const auto* p = static_cast<const std::uint8_t*>(ivPtr);
            c.iv.assign(p, p + ivLen);
        }

        c.notes      = read_text_nullable(stmt.get(), 5);
        c.created_at = read_text_nullable(stmt.get(), 6);

        out.push_back(std::move(c));
    }
    if (rc != SQLITE_DONE) {
        throw std::runtime_error(std::string("step searchByService failed: ")
                                 + sqlite3_errmsg(m_db));
    }

    return out;
}

void DatabaseManager::updateCredential(int id,
                                       const std::string& newUsername,
                                       const std::vector<std::uint8_t>& newEncPassword,
                                       const std::vector<std::uint8_t>& newIv,
                                       const std::string& newNotes) {
    const char* sql = R"SQL(
        UPDATE credentials
        SET username = ?, encrypted_password = ?, iv = ?, notes = ?
        WHERE id = ?;
    )SQL";

    sqlite3_stmt* stmtRaw = nullptr;
    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(std::string("prepare updateCredential failed: ")
                                 + sqlite3_errmsg(m_db));
    }
    std::unique_ptr<sqlite3_stmt, StmtCloser> stmt(stmtRaw);

    auto bind_ok = [&](int code, const char* what) {
        if (code != SQLITE_OK) {
            throw std::runtime_error(std::string(what) + ": " + sqlite3_errmsg(m_db));
        }
    };

    bind_ok(sqlite3_bind_text(stmt.get(), 1, newUsername.c_str(), -1, SQLITE_TRANSIENT), "bind username");
    bind_ok(sqlite3_bind_blob(stmt.get(), 2, newEncPassword.data(),
                              static_cast<int>(newEncPassword.size()), SQLITE_TRANSIENT), "bind enc");
    bind_ok(sqlite3_bind_blob(stmt.get(), 3, newIv.data(),
                              static_cast<int>(newIv.size()),          SQLITE_TRANSIENT), "bind iv");
    bind_ok(sqlite3_bind_text(stmt.get(), 4, newNotes.c_str(), -1, SQLITE_TRANSIENT), "bind notes");
    bind_ok(sqlite3_bind_int (stmt.get(), 5, id), "bind id");

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        throw std::runtime_error(std::string("updateCredential step failed: ")
                                 + sqlite3_errmsg(m_db));
    }
}

void DatabaseManager::deleteCredential(int id) {
    const char* sql = "DELETE FROM credentials WHERE id = ?;";

    sqlite3_stmt* stmtRaw = nullptr;
    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(std::string("prepare deleteCredential failed: ")
                                 + sqlite3_errmsg(m_db));
    }
    std::unique_ptr<sqlite3_stmt, StmtCloser> stmt(stmtRaw);

    rc = sqlite3_bind_int(stmt.get(), 1, id);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(std::string("bind id failed: ") + sqlite3_errmsg(m_db));
    }

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        throw std::runtime_error(std::string("deleteCredential step failed: ")
                                 + sqlite3_errmsg(m_db));
    }
}

// ---- Test helper and transactions ----

void DatabaseManager::test_updateCreatedAt(int id, const std::string& createdAt) {
    // Safer: bind instead of string concatenation
    const char* sql = "UPDATE credentials SET created_at = ? WHERE id = ?;";
    sqlite3_stmt* stmtRaw = nullptr;
    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(std::string("prepare test_updateCreatedAt failed: ")
                                 + sqlite3_errmsg(m_db));
    }
    std::unique_ptr<sqlite3_stmt, StmtCloser> stmt(stmtRaw);

    rc = sqlite3_bind_text(stmt.get(), 1, createdAt.c_str(), -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) throw std::runtime_error(std::string("bind ts failed: ") + sqlite3_errmsg(m_db));

    rc = sqlite3_bind_int(stmt.get(), 2, id);
    if (rc != SQLITE_OK) throw std::runtime_error(std::string("bind id failed: ") + sqlite3_errmsg(m_db));

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        throw std::runtime_error(std::string("step test_updateCreatedAt failed: ")
                                 + sqlite3_errmsg(m_db));
    }
}

void DatabaseManager::beginTransaction() { exec("BEGIN IMMEDIATE;"); }
void DatabaseManager::commit()           { exec("COMMIT;"); }
void DatabaseManager::rollback()         { exec("ROLLBACK;"); }

// ---- Bulk fetch used by change-master ----

std::vector<CredentialRow> DatabaseManager::getAllCredentials() const {
    const char* sql = R"SQL(
        SELECT id, service, username, encrypted_password, iv, created_at, notes
        FROM credentials
        ORDER BY created_at DESC, id DESC;
    )SQL";

    sqlite3_stmt* stmtRaw = nullptr;
    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmtRaw, nullptr);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(std::string("prepare getAllCredentials failed: ")
                                 + sqlite3_errmsg(m_db));
    }
    std::unique_ptr<sqlite3_stmt, StmtCloser> stmt(stmtRaw);

    std::vector<CredentialRow> out;
    while ((rc = sqlite3_step(stmt.get())) == SQLITE_ROW) {
        CredentialRow r{};
        r.id        = sqlite3_column_int(stmt.get(), 0);
        r.service   = read_text_nullable(stmt.get(), 1);
        r.username  = read_text_nullable(stmt.get(), 2);

        const void* encPtr = sqlite3_column_blob(stmt.get(), 3);
        int encLen = sqlite3_column_bytes(stmt.get(), 3);
        if (encPtr && encLen > 0) {
            const auto* p = static_cast<const std::uint8_t*>(encPtr);
            r.enc_password.assign(p, p + encLen);
        }

        const void* ivPtr = sqlite3_column_blob(stmt.get(), 4);
        int ivLen = sqlite3_column_bytes(stmt.get(), 4);
        if (ivPtr && ivLen > 0) {
            const auto* p = static_cast<const std::uint8_t*>(ivPtr);
            r.iv.assign(p, p + ivLen);
        }

        r.created_at = read_text_nullable(stmt.get(), 5);
        r.notes      = read_text_nullable(stmt.get(), 6);

        out.push_back(std::move(r));
    }
    if (rc != SQLITE_DONE) {
        throw std::runtime_error(std::string("step getAllCredentials failed: ")
                                 + sqlite3_errmsg(m_db));
    }

    return out;
}
