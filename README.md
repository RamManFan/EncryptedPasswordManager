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
## 📸 Demo (Step by Step)

1. **Launch program**  
<img width="569" height="681" alt="image" src="https://github.com/user-attachments/assets/0a37127b-eb01-4f61-94fa-911110487839" />


2. **Generate Password**  
<img width="520" height="230" alt="image" src="https://github.com/user-attachments/assets/7679e36f-952f-474d-aed3-400c3bce376c" />


3. **Add a credential**  
<img width="567" height="597" alt="image" src="https://github.com/user-attachments/assets/783633d7-ab72-4f96-88b0-2ea1a5ad8c6a" />


4. **Search credentials**  
<img width="571" height="233" alt="image" src="https://github.com/user-attachments/assets/2bbc75e3-07fc-49fe-86a1-46098782df3a" />
 

5. **Update credentials**  
<img width="572" height="596" alt="image" src="https://github.com/user-attachments/assets/9e45d873-6291-4c4f-bd6c-961eeb544ff1" />


6. **Delete credentials**  
<img width="572" height="360" alt="29" src="https://github.com/user-attachments/assets/7ecef940-4e01-4409-b07b-ae06ee36e764" />


7. **GUI Tray App** (Windows only)  
<img width="394" height="252" alt="image" src="https://github.com/user-attachments/assets/946c6217-dce1-44a5-84f2-a865a3ab57e5" />


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
