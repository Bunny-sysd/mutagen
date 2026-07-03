/*
 * TARGET 21: DECOMPRESSION GLOBAL STATE REUSE (CVE-2026-41992 CONCEPT)
 * ======================================================================
 *
 * This target models a multi-format decompression parser (LZW vs LZH)
 * that shares a global execution state via a union.
 * 
 * VULNERABILITY:
 * When switching formats, the decompressor resets format flags but fails to
 * clear the active dictionary sizes, offsets, or clear memory pointers inside the 
 * shared context union. By sending format switch commands, LZH table writes
 * will corrupt active LZW string pointers, causing an access violation or double free.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DICT_ENTRIES 16

typedef struct {
    char* strings[MAX_DICT_ENTRIES];
    int lengths[MAX_DICT_ENTRIES];
} LZWContext;

typedef struct {
    int bit_lengths[MAX_DICT_ENTRIES];
    int symbol_map[MAX_DICT_ENTRIES]; // Overlaps with LZWContext strings pointer array!
} LZHContext;

typedef struct {
    int format; // 1 = LZW, 2 = LZH
    int active_dict_size;
    union {
        LZWContext lzw;
        LZHContext lzh;
    } ctx;
} DecompressorState;

DecompressorState g_state;

void init_decompressor() {
    g_state.format = 0;
    g_state.active_dict_size = 0;
    memset(&g_state.ctx, 0, sizeof(g_state.ctx));
}

void set_format(int new_format) {
    // VULNERABILITY: Switching formats changes the active union field,
    // but the system fails to clear the dirty pointers in g_state.ctx.lzw.strings!
    // It also fails to reset g_state.active_dict_size.
    g_state.format = new_format;
}

void handle_lzw_define(int index, const char* str) {
    if (g_state.format != 1) {
        printf("Error: LZW format not active\n");
        return;
    }
    if (index < 0 || index >= MAX_DICT_ENTRIES) {
        return;
    }
    
    // Allocate entry string
    if (g_state.ctx.lzw.strings[index]) {
        free(g_state.ctx.lzw.strings[index]);
    }
    g_state.ctx.lzw.strings[index] = strdup(str);
    g_state.ctx.lzw.lengths[index] = strlen(str);
    if (index >= g_state.active_dict_size) {
        g_state.active_dict_size = index + 1;
    }
}

void handle_lzh_setup(int index, int symbol_val) {
    if (g_state.format != 2) {
        printf("Error: LZH format not active\n");
        return;
    }
    if (index < 0 || index >= MAX_DICT_ENTRIES) {
        return;
    }
    
    // VULNERABLE OPERATION:
    // Writing to ctx.lzh.symbol_map corrupts the ctx.lzw.strings pointer array!
    // Since ctx is a union, lzh.symbol_map and lzw.strings share the same memory offset.
    // Overwriting symbol_map[index] overwrites strings[index] with a low integer value.
    g_state.ctx.lzh.symbol_map[index] = symbol_val;
}

void cleanup_state() {
    // Free strings to avoid leaks
    if (g_state.format == 1 || g_state.format == 2) {
        for (int i = 0; i < MAX_DICT_ENTRIES; i++) {
            // CRASH POINT: If symbol_map was written, g_state.ctx.lzw.strings[i]
            // contains a corrupted pointer (e.g. 0x00000041). Calling free() on it
            // triggers a segmentation fault / access violation.
            if (g_state.ctx.lzw.strings[i]) {
                free(g_state.ctx.lzw.strings[i]);
                g_state.ctx.lzw.strings[i] = NULL;
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <hex_commands>\n", argv[0]);
        return 0;
    }

    char* hex = argv[1];
    int len = strlen(hex);
    if (len % 2 != 0) {
        printf("Invalid hex command string.\n");
        return 1;
    }

    init_decompressor();

    int byte_len = len / 2;
    unsigned char* cmd = malloc(byte_len);
    if (!cmd) return 1;

    for (int i = 0; i < byte_len; i++) {
        unsigned int val;
        sscanf(&hex[i * 2], "%2x", &val);
        cmd[i] = (unsigned char)val;
    }

    int ip = 0;
    while (ip < byte_len) {
        unsigned char opcode = cmd[ip++];
        if (opcode == 0x01) {
            // Switch to LZW
            set_format(1);
        } else if (opcode == 0x02) {
            // Switch to LZH
            set_format(2);
        } else if (opcode == 0x03) {
            // LZW Define Entry: 03 <index_byte> <char_val>
            if (ip + 2 > byte_len) break;
            int index = cmd[ip++];
            char val_char = cmd[ip++];
            char temp_str[2] = {val_char, '\0'};
            handle_lzw_define(index, temp_str);
        } else if (opcode == 0x04) {
            // LZH Write Symbol Map: 04 <index_byte> <symbol_val_byte>
            if (ip + 2 > byte_len) break;
            int index = cmd[ip++];
            int symbol_val = cmd[ip++];
            handle_lzh_setup(index, symbol_val);
        }
    }

    free(cmd);
    
    // Trigger cleanup (will crash if corruption occurred)
    cleanup_state();

    printf("Decompression processing finished successfully.\n");
    return 0;
}
