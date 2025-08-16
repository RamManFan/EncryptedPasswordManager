#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <memory>
#include <sstream>
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
            MessageBox(hwnd, L"TODO: Implement Add credential UI", L"Info", MB_OK);
            break;
        case ID_BTN_SEARCH:
            MessageBox(hwnd, L"TODO: Implement Search by service UI", L"Info", MB_OK);
            break;
        case ID_BTN_VIEW:
            MessageBox(hwnd, L"TODO: Implement View by ID UI", L"Info", MB_OK);
            break;
        case ID_BTN_UPDATE:
            MessageBox(hwnd, L"TODO: Implement Update by ID UI", L"Info", MB_OK);
            break;
        case ID_BTN_DELETE:
            MessageBox(hwnd, L"TODO: Implement Delete by ID UI", L"Info", MB_OK);
            break;
        case ID_BTN_GEN:
            OnGeneratePassword(hwnd);
            break;
        case ID_BTN_LIST:
            OnListAll(hwnd);
            break;
        case ID_BTN_CHANGE:
            MessageBox(hwnd, L"TODO: Implement Change master password UI", L"Info", MB_OK);
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
