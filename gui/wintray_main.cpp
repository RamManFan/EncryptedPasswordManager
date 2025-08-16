#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <memory>
#include <sstream>
#include <ctime>
#include <stdexcept>
#include <openssl/rand.h>

#include "resource.h"
#include "DatabaseManager.hpp"
#include "AuthManager.hpp"
#include "EncryptionManager.hpp"
#include "password_gen.hpp"

// Globals
HINSTANCE g_hInst = nullptr;
HWND g_mainWnd = nullptr;
HWND g_menuWnd = nullptr;
NOTIFYICONDATA g_nid{};
bool g_loginOpen = false;
std::unique_ptr<DatabaseManager> g_db;
std::unique_ptr<EncryptionManager> g_enc;

// Forward declarations
LRESULT CALLBACK MainWndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK MenuWndProc(HWND, UINT, WPARAM, LPARAM);

// ---- Login dialog helpers -------------------------------------------------
namespace {
static std::string g_loginPw;
static bool g_loginOk = false;
static bool g_loginDone = false;

std::string narrow(const std::wstring& ws) {
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, s.data(), len, nullptr, nullptr);
    return s;
}

LRESULT CALLBACK LoginWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_OK: {
            wchar_t buf[256];
            GetWindowText(GetDlgItem(hwnd, IDC_EDIT_PASSWORD), buf, 256);
            g_loginPw = narrow(buf);
            g_loginOk = true;
            DestroyWindow(hwnd);
            return 0;
        }
        case IDC_BTN_CANCEL:
            g_loginPw.clear();
            g_loginOk = false;
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    case WM_KEYDOWN:
        if (wParam == VK_RETURN) {
            SendMessage(hwnd, WM_COMMAND, IDC_BTN_OK, 0);
        } else if (wParam == VK_ESCAPE) {
            SendMessage(hwnd, WM_COMMAND, IDC_BTN_CANCEL, 0);
        }
        break;
    case WM_DESTROY:
        g_loginDone = true;
        break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

bool ShowPasswordDialog(HWND owner, std::string& outPw) {
    WNDCLASS wc{};
    wc.lpfnWndProc = LoginWndProc;
    wc.hInstance = g_hInst;
    wc.lpszClassName = L"EpmLoginClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(WS_EX_DLGMODALFRAME, wc.lpszClassName, L"Enter Master Password",
        WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 260, 120,
        owner, nullptr, g_hInst, nullptr);

    CreateWindow(L"STATIC", L"Master password:", WS_CHILD | WS_VISIBLE,
        10, 10, 230, 20, hwnd, nullptr, g_hInst, nullptr);
    HWND hEdit = CreateWindowEx(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_PASSWORD | WS_TABSTOP,
        10, 30, 230, 20, hwnd, (HMENU)IDC_EDIT_PASSWORD, g_hInst, nullptr);
    CreateWindow(L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        50, 60, 70, 24, hwnd, (HMENU)IDC_BTN_OK, g_hInst, nullptr);
    CreateWindow(L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        130, 60, 70, 24, hwnd, (HMENU)IDC_BTN_CANCEL, g_hInst, nullptr);
    SetFocus(hEdit);

    RECT rc; GetWindowRect(hwnd, &rc);
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    SetWindowPos(hwnd, nullptr,
        (GetSystemMetrics(SM_CXSCREEN) - w) / 2,
        (GetSystemMetrics(SM_CYSCREEN) - h) / 2,
        0, 0, SWP_NOSIZE);

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    g_loginDone = false;
    MSG msg;
    while (!g_loginDone && GetMessage(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessage(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    if (g_loginOk) {
        outPw = g_loginPw;
    }
    return g_loginOk;
}
}

bool PromptLogin(HWND owner) {
    if (g_enc) return true; // already logged in
    g_loginOpen = true;
    bool authed = false;
    std::string pw;
    while (ShowPasswordDialog(owner, pw)) {
        try {
            CreateDirectoryA("data", nullptr);
            g_db = std::make_unique<DatabaseManager>("data/epm.sqlite");
            g_db->init();

            AuthManager auth;
            auto master = g_db->loadMaster();
            if (!master) {
                if (pw.empty()) {
                    MessageBox(owner, L"Password cannot be empty", L"Error", MB_OK | MB_ICONERROR);
                    continue;
                }
                StoredAuth rec = auth.createMasterRecord(pw);
                g_db->storeMaster(rec.salt, rec.hash);
                std::vector<std::uint8_t> salt(16);
                RAND_bytes(salt.data(), static_cast<int>(salt.size()));
                g_db->storeKdfSalt(salt);
                auto key = EncryptionManager::deriveKey(pw, salt);
                g_enc = std::make_unique<EncryptionManager>(key);
                authed = true;
                break;
            } else {
                StoredAuth stored{ master->first, master->second };
                if (!auth.verifyMasterPassword(pw, stored)) {
                    MessageBox(owner, L"Incorrect password", L"Error", MB_OK | MB_ICONERROR);
                    continue;
                }
                auto kdfSaltOpt = g_db->loadKdfSalt();
                std::vector<std::uint8_t> salt;
                if (kdfSaltOpt) {
                    salt = *kdfSaltOpt;
                } else {
                    salt.resize(16);
                    RAND_bytes(salt.data(), static_cast<int>(salt.size()));
                    g_db->storeKdfSalt(salt);
                }
                auto key = EncryptionManager::deriveKey(pw, salt);
                g_enc = std::make_unique<EncryptionManager>(key);
                authed = true;
                break;
            }
        } catch (const std::exception& e) {
            MessageBoxA(owner, e.what(), "Error", MB_OK | MB_ICONERROR);
        }
    }
    g_loginOpen = false;
    return authed;
}

// ---- Main menu ------------------------------------------------------------
namespace {
struct Field {
    int id;
    const wchar_t* label;
    bool password = false;
};

static std::vector<HWND> g_inputEdits;
static std::vector<std::string> g_inputVals;
static bool g_inputOk = false;
static bool g_inputDone = false;
static const std::vector<Field>* g_inputFields = nullptr;

LRESULT CALLBACK InputWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        for (size_t i = 0; i < g_inputFields->size(); ++i) {
            int y = 10 + static_cast<int>(i) * 30;
            const Field& f = (*g_inputFields)[i];
            CreateWindow(L"STATIC", f.label, WS_CHILD | WS_VISIBLE,
                10, y, 260, 20, hwnd, nullptr, g_hInst, nullptr);
            DWORD style = WS_CHILD | WS_VISIBLE | WS_TABSTOP;
            if (f.password) style |= ES_PASSWORD;
            HWND edit = CreateWindowEx(0, L"EDIT", L"", style,
                10, y + 20, 260, 20, hwnd, (HMENU)f.id, g_hInst, nullptr);
            g_inputEdits.push_back(edit);
        }
        int y = 10 + static_cast<int>(g_inputFields->size()) * 30;
        CreateWindow(L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            60, y, 80, 24, hwnd, (HMENU)IDC_BTN_OK, g_hInst, nullptr);
        CreateWindow(L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            160, y, 80, 24, hwnd, (HMENU)IDC_BTN_CANCEL, g_hInst, nullptr);
        if (!g_inputEdits.empty()) SetFocus(g_inputEdits[0]);
        break;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_OK: {
            wchar_t buf[512];
            g_inputVals.clear();
            for (HWND e : g_inputEdits) {
                GetWindowText(e, buf, 512);
                g_inputVals.push_back(narrow(buf));
            }
            g_inputOk = true;
            DestroyWindow(hwnd);
            return 0;
        }
        case IDC_BTN_CANCEL:
            g_inputOk = false;
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    case WM_KEYDOWN:
        if (wParam == VK_RETURN) {
            SendMessage(hwnd, WM_COMMAND, IDC_BTN_OK, 0);
        } else if (wParam == VK_ESCAPE) {
            SendMessage(hwnd, WM_COMMAND, IDC_BTN_CANCEL, 0);
        }
        break;
    case WM_DESTROY:
        g_inputDone = true;
        break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

bool ShowInputDialog(HWND owner, const wchar_t* title,
                     const std::vector<Field>& fields,
                     std::vector<std::string>& values) {
    g_inputFields = &fields;
    g_inputOk = false;
    g_inputDone = false;
    g_inputVals.clear();
    g_inputEdits.clear();

    WNDCLASS wc{};
    wc.lpfnWndProc = InputWndProc;
    wc.hInstance = g_hInst;
    wc.lpszClassName = L"EpmInputClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClass(&wc);

    int height = 70 + static_cast<int>(fields.size()) * 30;
    HWND hwnd = CreateWindowEx(WS_EX_DLGMODALFRAME, wc.lpszClassName, title,
        WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 300, height,
        owner, nullptr, g_hInst, nullptr);

    RECT rc; GetWindowRect(hwnd, &rc);
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    SetWindowPos(hwnd, nullptr,
        (GetSystemMetrics(SM_CXSCREEN) - w) / 2,
        (GetSystemMetrics(SM_CYSCREEN) - h) / 2,
        0, 0, SWP_NOSIZE);

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (!g_inputDone && GetMessage(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessage(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    if (g_inputOk) {
        values = g_inputVals;
    }
    return g_inputOk;
}


std::string isoNow() {
    std::time_t t = std::time(nullptr);
    std::tm tm;
    gmtime_s(&tm, &t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

enum MenuIds {
    ID_BTN_ADD = 60001,
    ID_BTN_SEARCH,
    ID_BTN_VIEW,
    ID_BTN_UPDATE,
    ID_BTN_DELETE,
    ID_BTN_GEN,
    ID_BTN_LIST,
    ID_BTN_CHANGE
};

void OnAddCredential(HWND hwnd) {
    if (!g_db || !g_enc) return;
    std::vector<Field> fields = {
        {IDC_EDIT_SERVICE, L"Service:"},
        {IDC_EDIT_USERNAME, L"Username:"},
        {IDC_EDIT_SECRET, L"Password/secret:", true},
        {IDC_EDIT_NOTES, L"Notes:"}
    };
    std::vector<std::string> vals;
    if (!ShowInputDialog(hwnd, L"Add credential", fields, vals)) return;
    try {
        std::string service = vals[0];
        std::string username = vals[1];
        std::string secret = vals[2];
        std::string notes = vals[3];
        std::string created = isoNow();
        std::string aadStr = service + "\n" + username + "\n" + created;
        std::vector<std::uint8_t> aad(aadStr.begin(), aadStr.end());
        std::vector<std::uint8_t> pt(secret.begin(), secret.end());
        auto encRes = g_enc->encrypt(pt, aad);
        int id = g_db->addCredential(service, username, encRes.encAndTag, encRes.iv, notes);
        MessageBoxA(hwnd, ("Added id " + std::to_string(id)).c_str(), "Success", MB_OK);
    } catch (const std::exception& e) {
        MessageBoxA(hwnd, e.what(), "Error", MB_OK | MB_ICONERROR);
    }
}

void OnSearchService(HWND hwnd) {
    if (!g_db) return;
    std::vector<Field> fields = { {IDC_EDIT_QUERY, L"Service substring:"} };
    std::vector<std::string> vals;
    if (!ShowInputDialog(hwnd, L"Search", fields, vals)) return;
    try {
        auto rows = g_db->searchByService(vals[0]);
        std::ostringstream oss;
        for (const auto& r : rows) {
            oss << r.id << " | " << r.service << " | " << r.username << " | " << r.created_at << "\n";
        }
        std::string text = oss.str();
        if (text.empty()) text = "(no matches)";
        MessageBoxA(hwnd, text.c_str(), "Search results", MB_OK);
    } catch (const std::exception& e) {
        MessageBoxA(hwnd, e.what(), "Error", MB_OK | MB_ICONERROR);
    }
}

void OnViewById(HWND hwnd) {
    if (!g_db || !g_enc) return;
    std::vector<Field> fields = { {IDC_EDIT_ID, L"Credential ID:"} };
    std::vector<std::string> vals;
    if (!ShowInputDialog(hwnd, L"View credential", fields, vals)) return;
    try {
        int id = std::stoi(vals[0]);
        auto rowOpt = g_db->getCredentialById(id);
        if (!rowOpt) {
            MessageBox(hwnd, L"ID not found", L"Error", MB_OK | MB_ICONERROR);
            return;
        }
        const Credential& r = *rowOpt;
        std::string aadStr = r.service + "\n" + r.username + "\n" + r.created_at;
        std::vector<std::uint8_t> aad(aadStr.begin(), aadStr.end());
        auto pt = g_enc->decrypt(r.iv, r.enc_password, aad);
        std::string secret(pt.begin(), pt.end());
        std::string msg = "Service: " + r.service + "\nUsername: " + r.username + "\nSecret: " + secret;
        MessageBoxA(hwnd, msg.c_str(), "Credential", MB_OK);
    } catch (const std::exception& e) {
        MessageBoxA(hwnd, e.what(), "Error", MB_OK | MB_ICONERROR);
    }
}

void OnUpdateById(HWND hwnd) {
    if (!g_db || !g_enc) return;
    std::vector<Field> fields = {
        {IDC_EDIT_ID, L"ID:"},
        {IDC_EDIT_NEW_USERNAME, L"New username:"},
        {IDC_EDIT_NEW_SECRET, L"New secret:", true},
        {IDC_EDIT_NEW_NOTES, L"New notes:"}
    };
    std::vector<std::string> vals;
    if (!ShowInputDialog(hwnd, L"Update credential", fields, vals)) return;
    try {
        int id = std::stoi(vals[0]);
        auto rowOpt = g_db->getCredentialById(id);
        if (!rowOpt) {
            MessageBox(hwnd, L"ID not found", L"Error", MB_OK | MB_ICONERROR);
            return;
        }
        Credential r = *rowOpt;
        std::string newUser = vals[1].empty() ? r.username : vals[1];
        std::string newNotes = vals[3].empty() ? r.notes : vals[3];
        std::vector<std::uint8_t> newEnc = r.enc_password;
        std::vector<std::uint8_t> newIv = r.iv;
        bool usernameChanged = newUser != r.username;
        if (!vals[2].empty() || usernameChanged) {
            std::string oldAadStr = r.service + "\n" + r.username + "\n" + r.created_at;
            std::vector<std::uint8_t> oldAad(oldAadStr.begin(), oldAadStr.end());
            auto pt = g_enc->decrypt(r.iv, r.enc_password, oldAad);
            if (!vals[2].empty()) {
                pt.assign(vals[2].begin(), vals[2].end());
            }
            std::string newAadStr = r.service + "\n" + newUser + "\n" + r.created_at;
            std::vector<std::uint8_t> newAad(newAadStr.begin(), newAadStr.end());
            auto encRes = g_enc->encrypt(pt, newAad);
            newEnc = encRes.encAndTag;
            newIv = encRes.iv;
        }
        g_db->updateCredential(id, newUser, newEnc, newIv, newNotes);
        MessageBox(hwnd, L"Updated", L"Info", MB_OK);
    } catch (const std::exception& e) {
        MessageBoxA(hwnd, e.what(), "Error", MB_OK | MB_ICONERROR);
    }
}

void OnDeleteById(HWND hwnd) {
    if (!g_db) return;
    std::vector<Field> fields = {
        {IDC_EDIT_ID, L"ID:"},
        {IDC_EDIT_CONFIRM, L"Type YES to confirm:"}
    };
    std::vector<std::string> vals;
    if (!ShowInputDialog(hwnd, L"Delete credential", fields, vals)) return;
    try {
        if (vals[1] != "YES") {
            MessageBox(hwnd, L"Confirmation failed", L"Error", MB_OK | MB_ICONERROR);
            return;
        }
        int id = std::stoi(vals[0]);
        g_db->deleteCredential(id);
        MessageBox(hwnd, L"Deleted", L"Info", MB_OK);
    } catch (const std::exception& e) {
        MessageBoxA(hwnd, e.what(), "Error", MB_OK | MB_ICONERROR);
    }
}

void OnChangeMaster(HWND hwnd) {
    if (!g_db || !g_enc) return;
    std::vector<Field> fields = {
        {IDC_EDIT_CUR_MASTER, L"Current password:", true},
        {IDC_EDIT_NEW_MASTER, L"New password:", true},
        {IDC_EDIT_CONFIRM_MASTER, L"Confirm new password:", true}
    };
    std::vector<std::string> vals;
    if (!ShowInputDialog(hwnd, L"Change master password", fields, vals)) return;
    std::string cur = vals[0];
    std::string nw = vals[1];
    std::string confirm = vals[2];
    if (nw != confirm) {
        MessageBox(hwnd, L"Passwords do not match", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    try {
        AuthManager auth;
        auto masterOpt = g_db->loadMaster();
        if (!masterOpt) {
            MessageBox(hwnd, L"No master record", L"Error", MB_OK | MB_ICONERROR);
            return;
        }
        StoredAuth stored{ masterOpt->first, masterOpt->second };
        if (!auth.verifyMasterPassword(cur, stored)) {
            MessageBox(hwnd, L"Incorrect password", L"Error", MB_OK | MB_ICONERROR);
            return;
        }
        g_db->beginTransaction();
        auto rows = g_db->getAllCredentials();
        auto oldSaltOpt = g_db->loadKdfSalt();
        if (!oldSaltOpt) {
            throw std::runtime_error("Missing KDF salt");
        }
        auto oldKey = EncryptionManager::deriveKey(cur, *oldSaltOpt);
        EncryptionManager encOld(oldKey);
        std::vector<std::uint8_t> newSalt(16);
        RAND_bytes(newSalt.data(), (int)newSalt.size());
        auto newKey = EncryptionManager::deriveKey(nw, newSalt);
        EncryptionManager encNew(newKey);
        for (const auto& r : rows) {
            std::string aadStr = r.service + "\n" + r.username + "\n" + r.created_at;
            std::vector<std::uint8_t> aad(aadStr.begin(), aadStr.end());
            auto pt = encOld.decrypt(r.iv, r.enc_password, aad);
            auto encRes = encNew.encrypt(pt, aad);
            g_db->updateCredential(r.id, r.username, encRes.encAndTag, encRes.iv, r.notes);
        }
        StoredAuth newRec = auth.createMasterRecord(nw);
        g_db->storeKdfSalt(newSalt);
        g_db->storeMaster(newRec.salt, newRec.hash);
        g_db->commit();
        g_enc = std::make_unique<EncryptionManager>(newKey);
        MessageBox(hwnd, L"Master password changed", L"Info", MB_OK);
    } catch (const std::exception& e) {
        g_db->rollback();
        MessageBoxA(hwnd, e.what(), "Error", MB_OK | MB_ICONERROR);
    }
}
void OnListAll(HWND hwnd) {
    if (!g_db) return;
    try {
        auto rows = g_db->getAllCredentials();
        std::ostringstream oss;
        for (const auto& r : rows) {
            oss << r.id << " | " << r.service << " | " << r.username << " | " << r.created_at << "\n";
        }
        std::string text = oss.str();
        if (text.empty()) text = "(no credentials)";
        MessageBoxA(hwnd, text.c_str(), "Credentials", MB_OK);
    } catch (const std::exception& e) {
        MessageBoxA(hwnd, e.what(), "Error", MB_OK | MB_ICONERROR);
    }
}

void OnGeneratePassword(HWND hwnd) {
    try {
        std::string pw = generate_password(16);
        if (OpenClipboard(hwnd)) {
            EmptyClipboard();
            HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, pw.size() + 1);
            if (hMem) {
                char* ptr = static_cast<char*>(GlobalLock(hMem));
                memcpy(ptr, pw.c_str(), pw.size() + 1);
                GlobalUnlock(hMem);
                SetClipboardData(CF_TEXT, hMem);
            }
            CloseClipboard();
        }
        MessageBoxA(hwnd, pw.c_str(), "Generated password (copied to clipboard)", MB_OK);
    } catch (const std::exception& e) {
        MessageBoxA(hwnd, e.what(), "Error", MB_OK | MB_ICONERROR);
    }
}

} // namespace

void ShowMainMenu() {
    if (!g_menuWnd) {
        WNDCLASS wc{};
        wc.lpfnWndProc = MenuWndProc;
        wc.hInstance = g_hInst;
        wc.lpszClassName = L"EpmMenuClass";
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        RegisterClass(&wc);

        g_menuWnd = CreateWindow(wc.lpszClassName, L"EPM Menu",
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
            CW_USEDEFAULT, CW_USEDEFAULT, 300, 280,
            g_mainWnd, nullptr, g_hInst, nullptr);

        const wchar_t* labels[8] = {
            L"Add credential",
            L"Search by service",
            L"View (decrypt) by ID",
            L"Update by ID",
            L"Delete by ID",
            L"Generate password",
            L"List all credentials",
            L"Change master password"
        };
        const int ids[8] = {
            ID_BTN_ADD, ID_BTN_SEARCH, ID_BTN_VIEW, ID_BTN_UPDATE,
            ID_BTN_DELETE, ID_BTN_GEN, ID_BTN_LIST, ID_BTN_CHANGE
        };
        for (int i = 0; i < 8; ++i) {
            CreateWindow(L"BUTTON", labels[i], WS_CHILD | WS_VISIBLE,
                10, 10 + i * 30, 260, 24, g_menuWnd, (HMENU)ids[i], g_hInst, nullptr);
        }
    }
    ShowWindow(g_menuWnd, SW_SHOW);
    UpdateWindow(g_menuWnd);
}

LRESULT CALLBACK MenuWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_BTN_ADD:
            OnAddCredential(hwnd);
            break;
        case ID_BTN_SEARCH:
            OnSearchService(hwnd);
            break;
        case ID_BTN_VIEW:
            OnViewById(hwnd);
            break;
        case ID_BTN_UPDATE:
            OnUpdateById(hwnd);
            break;
        case ID_BTN_DELETE:
            OnDeleteById(hwnd);
            break;
        case ID_BTN_GEN:
            OnGeneratePassword(hwnd);
            break;
        case ID_BTN_LIST:
            OnListAll(hwnd);
            break;
        case ID_BTN_CHANGE:
            OnChangeMaster(hwnd);
            break;
        }
        break;
    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// ---- Tray window ---------------------------------------------------------
LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WMAPP_TRAY:
        if (LOWORD(lParam) == WM_LBUTTONUP || LOWORD(lParam) == WM_LBUTTONDBLCLK) {
            if (!g_loginOpen && PromptLogin(hwnd)) {
                ShowMainMenu();
            }
        } else if (LOWORD(lParam) == WM_RBUTTONUP) {
            HMENU hMenu = CreatePopupMenu();
            AppendMenu(hMenu, MF_STRING, IDM_TRAY_SHOW, L"Show");
            AppendMenu(hMenu, MF_STRING, IDM_TRAY_EXIT, L"Exit");
            POINT pt; GetCursorPos(&pt);
            SetForegroundWindow(hwnd);
            TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, nullptr);
            DestroyMenu(hMenu);
        }
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDM_TRAY_SHOW:
            if (!g_loginOpen && PromptLogin(hwnd)) {
                ShowMainMenu();
            }
            break;
        case IDM_TRAY_EXIT:
            DestroyWindow(hwnd);
            break;
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// ---- Entry point ---------------------------------------------------------
int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
    g_hInst = hInstance;

    WNDCLASS wc{};
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"EpmTrayClass";
    RegisterClass(&wc);

    g_mainWnd = CreateWindow(wc.lpszClassName, L"EPM", 0,
        0, 0, 0, 0, nullptr, nullptr, hInstance, nullptr);

    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = g_mainWnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_nid.uCallbackMessage = WMAPP_TRAY;
    g_nid.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    lstrcpyn(g_nid.szTip, L"EPM (click to unlock)", ARRAYSIZE(g_nid.szTip));
    Shell_NotifyIcon(NIM_ADD, &g_nid);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    Shell_NotifyIcon(NIM_DELETE, &g_nid);
    if (g_nid.hIcon) DestroyIcon(g_nid.hIcon);
    return 0;
}
