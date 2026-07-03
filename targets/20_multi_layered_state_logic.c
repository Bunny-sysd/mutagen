#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STATE_INIT        0
#define STATE_CHALLENGE   1
#define STATE_VERIFIED    2

typedef struct {
	char *username;
	char *session_data;
	int state;
} user_session_t;

void process_data(user_session_t *session, const char *data, int length) {
	// CWE-191: Integer Underflow leading to massive memcpy / buffer overflow
	// If length is less than 4 (e.g. 2), length - 4 becomes -2.
	// When passed to memcpy (which expects size_t), it gets promoted to a huge positive size_t (e.g., 18446744073709551614), causing segmentation fault or OOM.
	int payload_len = length - 4;

	if (session->state != STATE_VERIFIED) {
		printf("ERR: Access Denied\n");
		return;
	}

	char *buf = malloc(1024);
	if (!buf) return;

	// Dangerous copy without verifying payload_len >= 0
	memcpy(buf, data + 4, payload_len);
	buf[1023] = '\0';
	printf("Processed Payload: %s\n", buf);
	free(buf);
}

int main() {
	user_session_t *session = malloc(sizeof(user_session_t));
	if (!session) return 1;

	session->username = NULL;
	session->session_data = NULL;
	session->state = STATE_INIT;

	char line[1024];
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

	while (fgets(line, sizeof(line), stdin)) {
		// Strip newline
		size_t len = strlen(line);
		if (len > 0 && line[len - 1] == '\n') {
			line[len - 1] = '\0';
		}

		if (strncmp(line, "USER ", 5) == 0) {
			session->username = strdup(line + 5);
			session->state = STATE_CHALLENGE;
			printf("CHALLENGE: Send authentication token\n");
		} 
		else if (strncmp(line, "AUTH ", 5) == 0) {
			if (session->state != STATE_CHALLENGE) {
				printf("ERR: Call USER first\n");
				continue;
			}
			// Simple validation
			if (strcmp(line + 5, "SecretToken2026") == 0) {
				session->session_data = malloc(256);
				if (session->session_data) {
					strcpy(session->session_data, "ACTIVE_SESSION");
				}
				session->state = STATE_VERIFIED;
				printf("OK: Verified\n");
			} else {
				printf("ERR: Invalid token\n");
			}
		}
		else if (strncmp(line, "DATA ", 5) == 0) {
			// Read length from next input line, followed by the raw data
			char len_line[32];
			if (!fgets(len_line, sizeof(len_line), stdin)) break;
			int length = atoi(len_line);

			char data_line[1024];
			if (!fgets(data_line, sizeof(data_line), stdin)) break;

			process_data(session, data_line, length);
		}
		else if (strcmp(line, "LOGOUT") == 0) {
			// CWE-416: Use After Free logic flaw
			// We free the session_data and username, but do NOT reset the state to STATE_INIT!
			if (session->username) {
				free(session->username);
				session->username = NULL;
			}
			if (session->session_data) {
				free(session->session_data);
				// session->session_data is freed but not nullified, and state remains STATE_VERIFIED!
			}
			printf("OK: Logged out\n");
		}
		else if (strcmp(line, "STATUS") == 0) {
			// If the user called LOGOUT but state is still STATE_VERIFIED,
			// this prints session_data which was already freed!
			if (session->state == STATE_VERIFIED) {
				printf("Session Data: %s\n", session->session_data);
			} else {
				printf("Guest User\n");
			}
		}
		else if (strcmp(line, "EXIT") == 0) {
			break;
		}
	}

	if (session->username) free(session->username);
	if (session->session_data) free(session->session_data);
	free(session);
	return 0;
}
