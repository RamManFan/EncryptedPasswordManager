#pragma once
#include <string>

class UIManager {
public:
    void showMainMenu() const;
    std::string promptNonEmpty(const std::string& label) const;
    std::string promptHidden(const std::string& label) const; // no-echo password
    void printLine(const std::string& text) const;
};
