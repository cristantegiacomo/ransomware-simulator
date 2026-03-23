# Ransomware Simulator

---

## What is this?

This is a C program that simulates how ransomware works under the hood. It walks through a folder, encrypts every file it finds, and leaves a ransom note. Running it again decrypts everything back to the original state.

The goal was not to build something malicious — it was to understand how ransomware actually interacts with the operating system at a low level, using the same system calls a real program would use.

---

## What I learned building this

- How to navigate the file system recursively using `opendir` and `readdir`
- How files are actually stored as raw bytes and how to read/write them with `open`, `read`, and `write`
- How XOR encryption works
- How to build a safety boundary that prevents the program from ever touching files outside the test folder

---

## How to run it

**Build:**
```bash
cd src
make
```

**Encrypt the test folder:**
```bash
./ransomware -e ../victim_test
```

**Decrypt it back:**
```bash
./ransomware -d ../victim_test
```

**Verify everything was restored correctly:**
```bash
diff -r ../victim_test ../backup_files
```
No output means every byte is identical to the original.

---

## A note on the -e and -d flags

Because XOR is its own inverse, both flags perform the exact same operation on the bytes. The only real difference is that `-e` creates the ransom note and `-d` removes it. With a real encryption algorithm like AES the two would be completely different operations.

---

## Author

Giacomo Cristante
