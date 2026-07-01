#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_CHANNELS 4
#define MAX_PAYLOAD_SIZE 512

typedef enum {
    STATE_INIT,
    STATE_AUTH_CHALLENGE,
    STATE_CHANNEL_ACTIVE,
    STATE_TEARDOWN
} session_state_t;

#pragma pack(push, 1)
typedef struct {
    uint8_t channel_id;
    int16_t chunk_length;
    uint32_t sequence_num;
    uint8_t dynamic_checksum;
} packet_header_t;
#pragma pack(pop)

typedef struct {
    session_state_t state;
    uint32_t session_token;
    uint8_t active_channels[MAX_CHANNELS];
    int total_bytes_processed;
} session_context_t;

session_context_t g_ctx = {STATE_INIT, 0, {0}, 0};

void clear_session() {
    g_ctx.state = STATE_INIT;
    g_ctx.session_token = 0;
    memset(g_ctx.active_channels, 0, MAX_CHANNELS);
    g_ctx.total_bytes_processed = 0;
}

int verify_state_transition(packet_header_t* header) {
    if (g_ctx.state == STATE_INIT && header->sequence_num == 0x00000000) {
        g_ctx.session_token = 0xDEADC0DE;
        g_ctx.state = STATE_AUTH_CHALLENGE;
        return 1;
    }
    
    if (g_ctx.state == STATE_AUTH_CHALLENGE) {
        if (header->sequence_num == (g_ctx.session_token ^ 0x12345678)) {
            g_ctx.state = STATE_CHANNEL_ACTIVE;
            return 1;
        }
        clear_session();
        return 0;
    }
    
    if (g_ctx.state == STATE_CHANNEL_ACTIVE) {
        if (header->channel_id < MAX_CHANNELS) {
            return 1;
        }
    }
    return 0;
}

void process_packet_payload(packet_header_t* header, const uint8_t* raw_payload) {
    if (!verify_state_transition(header)) {
        return;
    }

    uint8_t* heap_buffer = (uint8_t*)malloc(MAX_PAYLOAD_SIZE);
    if (!heap_buffer) return;

    if (header->chunk_length >= 0 && header->chunk_length < MAX_PAYLOAD_SIZE) {
        memcpy(heap_buffer, raw_payload, header->chunk_length);
        g_ctx.total_bytes_processed += header->chunk_length;
        printf("Channel %d processed packet size: %d\n", header->channel_id, header->chunk_length);
    }

    free(heap_buffer);
}

int main(int argc, char* argv[]) {
    FILE* fp = stdin;
    if (argc >= 2 && strcmp(argv[1], "-") != 0) {
        fp = fopen(argv[1], "rb");
        if (!fp) return 1;
    }

    packet_header_t header;
    uint8_t payload_buffer[2048];

    while (fread(&header, sizeof(packet_header_t), 1, fp) == 1) {
        size_t bytes_to_read = (header.chunk_length > 0 && header.chunk_length < 2048) ? header.chunk_length : 256;
        size_t bytes_read = fread(payload_buffer, 1, bytes_to_read, fp);
        
        process_packet_payload(&header, payload_buffer);
    }

    if (fp != stdin) {
        fclose(fp);
    }
    return 0;
}
