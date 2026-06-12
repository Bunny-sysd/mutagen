/*
 * TARGET 04: USE-AFTER-FREE (CWE-416)
 * =====================================
 * CVE Examples: CVE-2022-22620 (WebKit/Safari), CVE-2021-22555 (Linux kernel)
 *
 * WHAT IS USE-AFTER-FREE?
 * When you call free() on a pointer, the memory is returned to the
 * system's allocator. But the POINTER itself still holds the old
 * address. If you USE that pointer after freeing, you're accessing
 * memory that might now belong to something else entirely.
 *
 * THE DANGER:
 *   1. free(ptr)           -- memory returned to allocator
 *   2. new_obj = malloc()  -- allocator gives out SAME memory
 *   3. ptr->execute()      -- old pointer calls into new_obj's data
 *   
 * If an attacker controls what gets allocated in step 2, they can
 * make step 3 execute arbitrary code. This is how Chrome, Safari,
 * and the Linux kernel get exploited in the wild.
 *
 * REAL-WORLD IMPACT:
 * - Safari zero-days (CVE-2022-22620, used in state-sponsored attacks)
 * - Linux kernel privilege escalation (CVE-2021-22555)
 * - Chrome renderer exploits (multiple CVEs yearly)
 *
 * NOTE: This is a simplified demonstration. Real UAF exploits in
 * browsers/kernels involve complex object lifetimes and heap feng shui.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[64];
    int id;
    void (*handler)(char *);  // Function pointer!
} Session;

void safe_handler(char *data) {
    printf("Handler processing: %s\n", data);
}

Session *create_session(char *username) {
    Session *s = (Session *)malloc(sizeof(Session));
    if (!s) return NULL;
    
    strncpy(s->name, username, 63);
    s->name[63] = '\0';
    s->id = 1337;
    s->handler = safe_handler;
    
    printf("[+] Session created for: %s (id=%d)\n", s->name, s->id);
    return s;
}

void delete_session(Session *s) {
    printf("[-] Session destroyed for: %s\n", s->name);
    free(s);
    // BUG: s is not set to NULL after free!
    // The caller still has a valid-looking pointer
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <username> <action>\n", argv[0]);
        printf("  Actions: create, use, delete\n");
        return 1;
    }
    
    char *username = argv[1];
    char *action = argv[2];
    
    // Create a session
    Session *session = create_session(username);
    
    if (strcmp(action, "delete") == 0) {
        // Free the session
        delete_session(session);
        
        // --- Added for demonstration: The "Heap Spray" ---
        // In a real UAF exploit, the attacker triggers an allocation of the 
        // same size immediately after the free to overwrite the freed memory.
        char *malicious_allocation = (char *)malloc(sizeof(Session));
        if (malicious_allocation) {
            memset(malicious_allocation, 'B', sizeof(Session)); // Overwrite function pointer with 0x42424242
        }
        // ---------------------------------------------------
        
        // VULNERABLE: Use-After-Free!
        // The session pointer is still used after being freed.
        // On some systems this crashes, on others it reads garbage,
        // and in the worst case, an attacker controls what's there.
        printf("[!] Accessing freed session...\n");
        printf("    Name: %s\n", session->name);      // UAF read
        printf("    ID: %d\n", session->id);            // UAF read
        
        // UAF function pointer call - this is where RCE happens
        // in real exploits. The function pointer now points to
        // whatever data was allocated in this memory after free().
        printf("[!] Calling handler on freed object...\n");
        session->handler("post-free data");             // UAF call!
        
    } else {
        // Normal use - no bug
        session->handler(action);
        delete_session(session);
    }
    
    return 0;
}
