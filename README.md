███████╗██████╗ ███╗   ███╗
██╔════╝██╔══██╗████╗ ████║
█████╗  ██████╔╝██╔████╔██║
██╔══╝  ██╔═══╝ ██║╚██╔╝██║
███████╗██║     ██║ ╚═╝ ██║
╚══════╝╚═╝     ╚═╝     ╚═╝
Encrypted Password Manager
A local-only password manager I built in C++ to learn about encryption, databases, and secure storage.
It uses Argon2id for hashing the master password and AES-256-GCM for encrypting credentials, all stored in SQLite.

css
Copy code
[ FEATURES ]
Set a master password and log in

Save credentials for different services

Search, view, update, and delete credentials

Generate random secure passwords

Change your master password (re-encrypts everything)

css
Copy code
[ REQUIREMENTS ]
Windows (MSYS2 / UCRT64)
Install:

bash
Copy code
pacman -S --needed \
  mingw-w64-ucrt-x86_64-toolchain \
  mingw-w64-ucrt-x86_64-cmake \
  mingw-w64-ucrt-x86_64-ninja \
  mingw-w64-ucrt-x86_64-openssl \
  mingw-w64-ucrt-x86_64-sqlite3 \
  mingw-w64-ucrt-x86_64-argon2 \
  git
Linux/macOS
Use your package manager to get:

scss
Copy code
cmake, ninja, openssl (dev), sqlite3 (dev), argon2 (dev), git
css
Copy code
[ BUILDING ]
bash
Copy code
rm -rf build
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=/ucrt64
cmake --build build
Outputs:

css
Copy code
epm.exe   → Main program
tests.exe → Optional tests
css
Copy code
[ RUNNING ]
bash
Copy code
./build/epm.exe
First time:

It will ask you to create a master password.

Use it to unlock your stored credentials later.

Menu:

pgsql
Copy code
1) Add credential
2) Search by service
3) View (decrypt) by id
4) Update by id
5) Delete by id
6) Generate password
7) List all credentials
8) Change master password
q) Quit
vbnet
Copy code
[ WHERE DATA IS STORED ]
All secrets are in:

bash
Copy code
data/epm.sqlite
This file is ignored by Git for safety.

css
Copy code
[ RUNNING TESTS ]
bash
Copy code
./build/tests.exe
css
Copy code
[ .GITIGNORE SUGGESTIONS ]
swift
Copy code
/build/
/data/
/cmake-build-*/
*.exe
*.dll
*.o
*.obj
*.a
*.lib
*.pdb
*.ninja
CMakeFiles/
CMakeCache.txt
css
Copy code
[ NOTES ]
This is a learning project, not a production-grade password manager.

Built to explore C++, encryption, and SQLite.

Runs locally — no internet or cloud storage.

Keep your master password safe. Lose it = lose access.
