#pragma once
#include <string>
#include <iostream>

#if defined(_WIN32)
  #include <windows.h>
#else
  #include <termios.h>
  #include <unistd.h>
#endif

inline std::string prompt_hidden(const std::string& message) {
    std::cout << message << std::flush;
    std::string out;

#if defined(_WIN32)
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    DWORD oldMode = mode;
    mode &= ~ENABLE_ECHO_INPUT;
    SetConsoleMode(hStdin, mode);
    std::getline(std::cin, out);
    SetConsoleMode(hStdin, oldMode);
#else
    termios oldt{};
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, out);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

    std::cout << "\n";
    return out;
}
