#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

void default_logger(const char *msg) {
    printf("[LOG] %s\n", msg);
}

struct DBRecord {
    char key[32];
    char value[64];
    int active;
    void (*log_fn)(const char *);
};

void trim_newline(char *str) {
    int len = strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[len - 1] = '\0';
        len--;
    }
}

int is_valid_key(const char *key) {
    if (strlen(key) == 0) return 0;
    for (int i = 0; key[i] != '\0'; i++) {
        if (!isalnum((unsigned char)key[i]) && key[i] != '_') {
            return 0;
        }
    }
    return 1;
}

void unescape_value(char *dest, const char *src, int max_len) {
    int s = 0;
    int d = 0;
    while (src[s] != '\0') {
        if (d >= max_len) {
            break;
        }
        if (src[s] == '\\' && src[s + 1] != '\0') {
            if (src[s + 1] == 'n') {
                dest[d++] = '\n';
                s += 2;
            } else if (src[s + 1] == 't') {
                dest[d++] = '\t';
                s += 2;
            } else {
                dest[d++] = src[s];
                s++;
            }
        } else {
            dest[d++] = src[s];
            s++;
        }
    }
    // VULNERABILITY: If d was incremented to max_len (64) in the loop, dest[d] is dest[64] which is out of bounds!
    dest[d] = '\0';
}

int parse_db_line(const char *line, struct DBRecord *record) {
    char *eq = strchr(line, '=');
    if (!eq) return 0;

    int key_len = eq - line;
    if (key_len >= sizeof(record->key)) {
        return 0;
    }
    strncpy(record->key, line, key_len);
    record->key[key_len] = '\0';

    if (!is_valid_key(record->key)) {
        return 0;
    }

    unescape_value(record->value, eq + 1, sizeof(record->value));
    return 1;
}

int main() {
    char line[256];
    struct DBRecord record;
    // Initialize record
    record.active = 1;
    record.log_fn = default_logger;
    memset(record.key, 0, sizeof(record.key));
    memset(record.value, 0, sizeof(record.value));

    if (fgets(line, sizeof(line), stdin) == NULL) {
        return 0;
    }

    trim_newline(line);
    
    if (parse_db_line(line, &record)) {
        if (!record.active) {
            printf("Corrupted active flag detected!\n");
            volatile int *p = NULL;
            *p = 42; // Force a deterministic crash!
        } else {
            record.log_fn("Parsed record successfully");
            printf("Key: %s\n", record.key);
            printf("Value: %s\n", record.value);
        }
    } else {
        printf("Failed to parse record.\n");
    }
    return 0;
}
