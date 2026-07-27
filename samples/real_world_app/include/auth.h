#ifndef AUTH_H
#define AUTH_H

typedef struct {
    char username[32];
    int is_admin;
} session_t;

int authenticate_user(const char *user_input, session_t *session);

#endif
