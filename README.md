# 🔐 Encrypted Password Manager (EPM)

```
███████╗██████╗ ███╗   ███╗
██╔════╝██╔══██╗████╗ ████║
█████╗  ██████╔╝██╔████╔██║
██╔══╝  ██╔═══╝ ██║╚██╔╝██║
███████╗██║     ██║ ╚═╝ ██║
╚══════╝╚═╝     ╚═╝     ╚═╝
```

A simple password manager I made as a learning project!  
Stores your passwords **encrypted** using AES-256, with a master password to keep everything safe.  
I’m still learning C++, so this project is my way of getting better and building something useful.

---

## 🚀 Features
- **Master password authentication** 🔑  
- **AES-256 encryption** for stored credentials  
- **Search by service name**  
- **Add, update, delete** credentials  
- **SQLite database** storage  

---

## 📦 How to Install

### 1️⃣ Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd YOUR_REPO
```

### 2️⃣ Install dependencies
Make sure you have:
- **C++ compiler** (GCC, Clang, or MSVC)  
- **CMake** (build system)  
- **SQLite3** library  

On Windows (MSYS2):
```bash
pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-sqlite3
```

On Linux (Debian/Ubuntu):
```bash
sudo apt install g++ cmake libsqlite3-dev
```

---

### 3️⃣ Build the project
```bash
mkdir build
cd build
cmake ..
cmake --build .
```

---

## 🛠 How to Use

### 1. Start the program
```bash
./epm
```

### 2. Set a master password  
First time running? You’ll be asked to create one.

### 3. Commands
- **Add** a credential → enter service, username, password  
- **Search** credentials by service name  
- **Update** existing credentials  
- **Delete** credentials you don’t need anymore  

### 4. Database file
The encrypted credentials are stored in:
```
data/epm.sqlite
```

---

## 🧹 Resetting the Database
If you want to start fresh:
```bash
rm data/epm.sqlite
```

---

## 📝 Notes
This is my learning project, so it’s not meant for serious password storage yet.  
I made it to get better at:
- C++ classes  
- File handling  
- SQLite database usage  
- Encryption techniques  

---

## 📄 License
MIT — Feel free to use this for learning and experimenting.
