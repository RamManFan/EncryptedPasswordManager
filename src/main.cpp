// src/main.cpp
#include "DatabaseManager.hpp"
#include "AuthManager.hpp"
#include "EncryptionManager.hpp"
#include "console_io.hpp"
#include "password_gen.hpp"

#include <filesystem>
#include <iostream>
#include <string>
#include <optional>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <limits>
#include <openssl/rand.h>

// ----- Small helpers -----

static std::string prompt_line(const std::string& message) {
    std::cout << message << std::flush;
    std::string s;
    std::getline(std::cin, s);
    return s;
}

static std::vector<std::uint8_t> toBytes(const std::string& s) {
    return { s.begin(), s.end() };
}

static std::vector<std::uint8_t> makeAAD(const Credential& c) {
    std::string aad = c.service + "\n" + c.username + "\n" + c.created_at;
    return toBytes(aad);
}

static std::vector<std::uint8_t> ensure_kdf_salt(DatabaseManager& db) {
    if (auto s = db.loadKdfSalt()) return *s;
    std::vector<std::uint8_t> salt(16);
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1)
        throw std::runtime_error("RAND_bytes failed for kdf_salt");
    db.storeKdfSalt(salt);
    return salt;
}

static void print_row_brief(const Credential& c) {
    std::cout << "  [" << c.id << "] " << c.service
              << "  user=" << c.username
              << "  created=" << c.created_at
              << "  (encLen=" << c.enc_password.size() << ")\n";
}

// ----- Menu actions -----

static void action_add(DatabaseManager& db, const EncryptionManager& enc) {
    std::string service  = prompt_line("Service: ");
    std::string username = prompt_line("Username: ");
    std::string secret   = prompt_line("Password/Secret: ");
    std::string notes    = prompt_line("Notes (optional): ");

    // Make the same ISO-8601 UTC timestamp format the DB uses (to keep AAD stable)
    auto now_iso = []() -> std::string {
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
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
        return std::string(buf);
    }();

    // Build AAD = service \n username \n created_at (same value we expect DB to store)
    const std::string aad_str = service + "\n" + username + "\n" + now_iso;
    const auto aad = toBytes(aad_str);

    // Encrypt the secret
    auto encRes = enc.encrypt(toBytes(secret), aad);

    // Insert the row with the ciphertext and IV
    int id = db.addCredential(service, username, encRes.encAndTag, encRes.iv, notes);

    // Optional: read back to confirm insert
    if (auto row = db.getCredentialById(id)) {
        std::cout << "Added credential with id " << id << "\n";
    } else {
        std::cerr << "Error: inserted row not found!\n";
    }
}


static void action_search(DatabaseManager& db) {
    std::string q = prompt_line("Search service (substring): ");
    auto rows = db.searchByService(q);
    if (rows.empty()) {
        std::cout << "No matches.\n";
        return;
    }
    for (const auto& r : rows) print_row_brief(r);
}

static void action_view(DatabaseManager& db, const EncryptionManager& enc) {
    int id = -1;
    try { id = std::stoi(prompt_line("Enter id to view: ")); }
    catch (...) { std::cout << "Invalid id.\n"; return; }

    auto row = db.getCredentialById(id);
    if (!row) { std::cout << "Not found.\n"; return; }

    try {
        auto pt = enc.decrypt(row->iv, row->enc_password, makeAAD(*row));
        std::cout << "-----\n";
        std::cout << "Service : " << row->service   << "\n";
        std::cout << "Username: " << row->username  << "\n";
        std::cout << "Notes   : " << row->notes     << "\n";
        std::cout << "Created : " << row->created_at<< "\n";
        std::cout << "Password: " << std::string(pt.begin(), pt.end()) << "\n";
        std::cout << "-----\n";
    } catch (const std::exception& ex) {
        std::cout << "Decrypt failed: " << ex.what() << "\n";
    }
}

static void action_update(DatabaseManager& db, const EncryptionManager& enc) {
    int id = -1;
    try { id = std::stoi(prompt_line("Enter id to update: ")); }
    catch (...) { std::cout << "Invalid id.\n"; return; }

    auto row = db.getCredentialById(id);
    if (!row) { std::cout << "Not found.\n"; return; }

    std::string newUser   = prompt_line("New username (blank=keep): ");
    std::string newSecret = prompt_line("New password/secret (blank=keep): ");
    std::string newNotes  = prompt_line("New notes (blank=keep): ");

    if (newUser.empty())   newUser   = row->username;
    if (newNotes.empty())  newNotes  = row->notes;

    auto aad = toBytes(row->service + "\n" + newUser + "\n" + row->created_at);
    std::vector<std::uint8_t> newCipher = row->enc_password;
    std::vector<std::uint8_t> newIv     = row->iv;

    if (!newSecret.empty()) {
        auto res = enc.encrypt(toBytes(newSecret), aad);
        newCipher = std::move(res.encAndTag);
        newIv     = std::move(res.iv);
    }

    db.updateCredential(id, newUser, newCipher, newIv, newNotes);
    std::cout << "Updated.\n";
}

static void action_delete(DatabaseManager& db) {
    int id = -1;
    try { id = std::stoi(prompt_line("Enter id to delete: ")); }
    catch (...) { std::cout << "Invalid id.\n"; return; }

    if (prompt_line("Type 'YES' to confirm deletion: ") == "YES") {
        db.deleteCredential(id);
        std::cout << "Deleted id " << id << ".\n";
    } else {
        std::cout << "Aborted.\n";
    }
}

static void action_generate_password() {
    std::string lenStr = prompt_line("Length (e.g. 20): ");
    std::size_t len = 0;
    try { len = static_cast<std::size_t>(std::stoul(lenStr)); } catch (...) { len = 20; }
    std::string includeSymbols = prompt_line("Include symbols? (y/N): ");

    bool useSymbols = (!includeSymbols.empty() && (includeSymbols[0]=='y' || includeSymbols[0]=='Y'));

    try {
        auto pw = generate_password(len == 0 ? 20 : len, true, true, true, useSymbols);
        std::cout << "Generated: " << pw << "\n";
        std::cout << "Tip: paste this when adding a credential.\n";
    } catch (const std::exception& ex) {
        std::cout << "Generator error: " << ex.what() << "\n";
    }
}

static void action_list_all(DatabaseManager& db) {
    auto rows = db.getAllCredentials();
    if (rows.empty()) {
        std::cout << "No credentials stored.\n";
        return;
    }
    for (const auto& r : rows) {
        std::cout << "  [" << r.id << "] " << r.service
                  << "  user=" << r.username
                  << "  created=" << r.created_at
                  << "  (encLen=" << r.enc_password.size() << ")\n";
    }
}

static bool action_change_master(DatabaseManager& db) {
    // 0) Verify current master password first
    auto master = db.loadMaster();
    if (!master) {
        std::cout << "No master record present.\n";
        return false;
    }
    std::string current = prompt_hidden("Current master password: ");
    {
        StoredAuth stored{ master->first, master->second };
        AuthManager auth;
        if (!auth.verifyMasterPassword(current, stored)) {
            std::cout << "Current password incorrect. Aborting.\n";
            std::fill(current.begin(), current.end(), '\0');
            return false;
        }
    }

    // 1) Prompt for new master twice
    std::string new1 = prompt_hidden("New master password: ");
    std::string new2 = prompt_hidden("Confirm new master password: ");
    if (new1.empty()) {
        std::cout << "Empty not allowed.\n";
        std::fill(current.begin(), current.end(), '\0');
        return false;
    }
    if (new1 != new2) {
        std::cout << "Mismatch.\n";
        std::fill(current.begin(), current.end(), '\0');
        std::fill(new1.begin(), new1.end(), '\0');
        std::fill(new2.begin(), new2.end(), '\0');
        return false;
    }

    // 2) Derive OLD key from existing kdf_salt
    auto oldKdfSaltOpt = db.loadKdfSalt();
    if (!oldKdfSaltOpt) {
        std::cout << "No KDF salt present. (Login once first to create it.)\n";
        std::fill(current.begin(), current.end(), '\0');
        std::fill(new1.begin(), new1.end(), '\0');
        std::fill(new2.begin(), new2.end(), '\0');
        return false;
    }
    const auto& oldKdfSalt = *oldKdfSaltOpt;
    auto oldKey = EncryptionManager::deriveKey(current, oldKdfSalt);
    EncryptionManager encOld(oldKey);

    // 3) Generate NEW kdf_salt and key
    std::vector<std::uint8_t> newKdfSalt(16);
    if (RAND_bytes(newKdfSalt.data(), static_cast<int>(newKdfSalt.size())) != 1) {
        std::cout << "RNG failed.\n";
        std::fill(current.begin(), current.end(), '\0');
        std::fill(new1.begin(), new1.end(), '\0');
        std::fill(new2.begin(), new2.end(), '\0');
        return false;
    }
    auto newKey = EncryptionManager::deriveKey(new1, newKdfSalt);
    EncryptionManager encNew(newKey);

    // 4) Re-encrypt everything inside a transaction
    try {
        db.beginTransaction(); // must use persistent connection

        auto rows = db.getAllCredentials(); // must include notes
        for (const auto& r : rows) {
            // AAD is stable triplet
            std::string aadStr = r.service + "\n" + r.username + "\n" + r.created_at;
            std::vector<std::uint8_t> aad(aadStr.begin(), aadStr.end());

            // decrypt with old key
            auto pt = encOld.decrypt(r.iv, r.enc_password, aad);

            // encrypt with new key
            auto encRes = encNew.encrypt(pt, aad);

            // update row — preserve username and notes; DO NOT change created_at
            db.updateCredential(r.id, r.username, encRes.encAndTag, encRes.iv, r.notes);

            // scrub plaintext asap
            std::fill(pt.begin(), pt.end(), 0);
        }

        // 5) Update app_settings.kdf_salt
        db.storeKdfSalt(newKdfSalt);

        // 6) Update master_auth {salt, hash} for the new master
        {
            AuthManager auth;
            StoredAuth newAuth = auth.createMasterRecord(new1);
            db.storeMaster(newAuth.salt, newAuth.hash);
        }

        db.commit();
        std::cout << "Master password changed. Re-encrypted all credentials.\n";

        // scrub secrets
        std::fill(current.begin(), current.end(), '\0');
        std::fill(new1.begin(), new1.end(), '\0');
        std::fill(new2.begin(), new2.end(), '\0');

        return true;
    } catch (const std::exception& ex) {
        try { db.rollback(); } catch (...) {}
        std::cout << "Change failed, rolled back: " << ex.what() << "\n";

        // scrub secrets even on failure
        std::fill(current.begin(), current.end(), '\0');
        std::fill(new1.begin(), new1.end(), '\0');
        std::fill(new2.begin(), new2.end(), '\0');

        return false;
    }
}


// ----- Main -----

int main() {
    try {
        std::cout << "EPM starting...\n";
        std::filesystem::create_directories("data");
        DatabaseManager db("data/epm.sqlite");
        db.init();

        AuthManager auth;
        auto master = db.loadMaster();

        if (!master.has_value()) {
            std::cout << "No master password found (first run).\n";
            std::string pw1 = prompt_hidden("Enter new master password: ");
            std::string pw2 = prompt_hidden("Confirm master password: ");

            if (pw1.empty() || pw1 != pw2) {
                std::cerr << "Invalid password.\n";
                return 1;
            }

            // ✅ Create once, store both pieces together
            StoredAuth rec = auth.createMasterRecord(pw1);
            db.storeMaster(rec.salt, rec.hash);

            std::cout << "Master password set. You can now log in.\n";
            return 0;
        }


        std::cout << "Master record found. Please log in.\n";
        std::string pw = prompt_hidden("Enter master password: ");
        if (!auth.verifyMasterPassword(pw, StoredAuth{ master->first, master->second })) {
            std::cerr << "Login failed ❌\n";
            return 2;
        }
        std::cout << "Login succesful\n";

        EncryptionManager enc(EncryptionManager::deriveKey(pw, ensure_kdf_salt(db)));

        for (;;) {
            std::cout << "\n=== Menu ===\n"
                         "1) Add credential\n"
                         "2) Search by service\n"
                         "3) View (decrypt) by id\n"
                         "4) Update by id\n"
                         "5) Delete by id\n"
                         "6) Generate password\n"
                         "7) List all credentials\n"
                         "8) change master password\n"
                         "q) Quit\n";
            std::string choice = prompt_line("> ");

            if (choice == "1") action_add(db, enc);
            else if (choice == "2") action_search(db);
            else if (choice == "3") action_view(db, enc);
            else if (choice == "4") action_update(db, enc);
            else if (choice == "5") action_delete(db);
            else if (choice == "6") action_generate_password();
            else if (choice == "7") action_list_all(db);
            else if (choice == "8") {
                if (action_change_master(db)) {
                    std::cout << "Please restart the app or log in again so the new key is used.\n";
                    break; // force exit to avoid using old EncryptionManager
                }
            }
            else if (choice == "q" || choice == "Q") break;
            else std::cout << "Unknown option.\n";
        }

        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[Fatal] " << ex.what() << "\n";
        return 99;
    }
}
