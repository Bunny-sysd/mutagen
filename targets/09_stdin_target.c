#include <stdio.h>
#include <string.h>

void process_input() {
    char buffer[64];
    printf("[*] Please enter your data: ");
    
    // VULNERABILITY: gets() is unsafe and causes buffer overflow
    gets(buffer);
    
    printf("[*] You entered: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    printf("[+] Starting STDIN Target\n");
    process_input();
    printf("[+] Exiting normally.\n");
    return 0;
}
