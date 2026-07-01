#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

typedef struct Node {
    char* data;
    struct Node* next;
} Node;

Node* global_head = NULL;
int processing_active = 0;

// The asynchronous interrupt
void emergency_cleanup_handler(int signum) {
    if (global_head && global_head->data) {
        free(global_head->data);
        // FLAW: Fails to set global_head->data to NULL after freeing
    }
}

void process_data_stream(const char* payload) {
    global_head = malloc(sizeof(Node));
    global_head->data = strdup(payload);
    processing_active = 1;

    // Simulate a time-intensive parsing operation
    for(int i = 0; i < 100000; i++) {
        if (i == 50000) {
            // FLAW: If the payload contains a specific byte sequence (e.g., "ABORT"),
            // it triggers a self-signal, interrupting the main execution thread.
            if (strstr(global_head->data, "ABORT")) {
                raise(SIGTERM); 
            }
        }
    }

    // THE CRASH: If the signal handler fired, global_head->data is now a dangling pointer.
    // The main thread resumes and attempts to read or write to freed memory.
    if (processing_active) {
        global_head->data[0] = 'X';
        printf("Processed: %c\n", global_head->data[0]); 
    }
    
    free(global_head->data); // Double-free corruption
    free(global_head);
}

int main(int argc, char* argv[]) {
    signal(SIGTERM, emergency_cleanup_handler);
    if (argc > 1) {
        process_data_stream(argv[1]);
    }
    return 0;
}
