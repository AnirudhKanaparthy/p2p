#ifndef STUN_H_
#define STUN_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "net.h"

#define STUN_HEADER_LEN 20
#define STUN_MAGIC_COOKIE 0x2112A442
#define STUN_TRANSACTION_ID_LEN 12
#define STUN_BINDING_RSP_TYPE 0x0101
#define STUN_XOR_MAPPED_ADDR_ATTR_TYPE 0x20
#define STUN_XOR_MAPPED_ADDR_LEN 8
#define STUN_ADDR_FAMILY_IPV4 0x01
#define STUN_ADDR_FAMILY_IPV6 0x02
#define STUN_RECV_BUFFER_LEN 512
#define STUN_DEFAULT_SERVER_IP "stun.l.google.com"
#define STUN_DEFAULT_SERVER_PORT 19302

// #define LOG_INFO(...) printf(__VA_ARGS__)
#define LOG_INFO(...) (void)0

#define FILL_INC(dst, type, val) (*(type*)(dst) = (val), (dst) = (void*)((type*)(dst) + 1))

typedef struct {
    Addr addr;
    uint8_t id[STUN_TRANSACTION_ID_LEN];
    uint16_t len;
} STUN_Rsp_Msg;

typedef struct {
    Addr private_addr;
    Addr public_addr;
} STUN_Addr_Map;


bool stun_fill_header(uint8_t* dst, size_t len);
bool stun_parse_rsp(STUN_Rsp_Msg* msg, const uint8_t* rsp, ssize_t len);
bool stun_default_server(Addr* dst);
int  stun_get_mapping(STUN_Addr_Map* dest, uint16_t local_port, const Addr* optional_stun_server_addr);

#endif // STUN_H_

#ifdef STUN_IMPLEMENTATION

#define NET_IMPLEMENTATION
#include "net.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static size_t fill_random(uint8_t* dst, size_t n) {
    if(!dst) return false;
    FILE* fd = fopen("/dev/urandom", "rb");
    if(!fd) return 0;
    size_t bytes_read = fread(dst, sizeof(uint8_t), n, fd);
    fclose(fd);
    return bytes_read;
}

bool stun_fill_header(uint8_t* dst, size_t len) {
    if(!dst) return false;
    if(len < STUN_HEADER_LEN) return false;
    memset(dst, 0, STUN_HEADER_LEN);

    FILL_INC(dst, uint16_t, htons(0x01)); // Message Type, Binding Request
    FILL_INC(dst, uint16_t, htons(0x00)); // Message Length (excluding header)
    FILL_INC(dst, uint32_t, htonl(STUN_MAGIC_COOKIE));
    return fill_random(dst, STUN_TRANSACTION_ID_LEN) == STUN_TRANSACTION_ID_LEN;
}

bool stun_parse_rsp(STUN_Rsp_Msg* msg, const uint8_t* rsp, ssize_t len) {
    if(!msg || len < 20) return false;
    const uint8_t* cur = rsp;
    
    // HEADER
    uint16_t msg_type = ntohs(*(uint16_t*)cur);
    cur += sizeof(uint16_t);
    if(msg_type != STUN_BINDING_RSP_TYPE) return false; // Not a correct STUN Binding method response

    msg->len = ntohs(*(uint16_t*)cur);
    cur += sizeof(uint16_t);
    if(len < (STUN_HEADER_LEN+msg->len)) return false;

    uint32_t msg_cookie = ntohl(*(uint32_t*)cur);
    cur += sizeof(uint32_t);

    if(msg_cookie != STUN_MAGIC_COOKIE) return false;

    // Transaction IDs are 96 bits so 3*4 bytes
    for(size_t i = 0; i < STUN_TRANSACTION_ID_LEN; ++i) {
        msg->id[i] = *cur++;
    }

    // ATTRIBUTES
    uint16_t attr_type = ntohs(*(uint16_t*)cur);
    cur += sizeof(uint16_t);
    if(attr_type != STUN_XOR_MAPPED_ADDR_ATTR_TYPE) return false;
    
    uint16_t attr_len = ntohs(*(uint16_t*)cur);
    cur += sizeof(uint16_t);
    if(attr_len != STUN_XOR_MAPPED_ADDR_LEN) return false;
    
    // ATTRIBUTE VALUE
    uint16_t addr_family = ntohs(*(uint16_t*)cur);
    cur += sizeof(uint16_t);

    switch(addr_family) {
        case STUN_ADDR_FAMILY_IPV4: {
            uint16_t xor_port = ntohs(*(uint16_t*)cur);
            cur += sizeof(uint16_t);

            uint32_t xor_ip = ntohl(*(uint32_t*)cur);
            cur += sizeof(uint32_t);

            msg->addr.port = ((STUN_MAGIC_COOKIE >> 16) ^ xor_port);
            uint32_t ip   = (STUN_MAGIC_COOKIE ^ xor_ip);

            uint8_t* ip_cur = (uint8_t*)&ip;
            memset(msg->addr.ip, 0, sizeof(msg->addr.ip));

            int ip_len = snprintf(msg->addr.ip, sizeof(msg->addr.ip)-1, "%d.%d.%d.%d", ip_cur[3], ip_cur[2], ip_cur[1], ip_cur[0]);
            if(ip_len < (int)(sizeof("0.0.0.0")-1) || ip_len > (int)(sizeof(msg->addr.ip)-1)) return false;
        } break;
        case STUN_ADDR_FAMILY_IPV6: {
            assert(0 && "TODO: Not implemented");
        } break;
        default: {
            assert(0 && "Unreachable");
        } break;
    }

    return true;
}

bool stun_default_server(Addr* dst) {
    if(!dst) return false;
    const char stun_domain[] = STUN_DEFAULT_SERVER_IP;

    char* stun_ip = resolve_domain(stun_domain);
    if(!stun_ip) {
        fprintf(stderr, "[ERR] Could not resolve address\n");
        return false;
    }

    dst->port=STUN_DEFAULT_SERVER_PORT;
    strncpy(dst->ip, stun_ip, sizeof(dst->ip) - 1);

    free(stun_ip);
    return true;
}

int stun_get_mapping(STUN_Addr_Map* dest, uint16_t local_port, const Addr* optional_stun_server_addr) {
    if(!dest) return false;
    Addr stun_server_addr;
    if(optional_stun_server_addr) {
        stun_server_addr = *optional_stun_server_addr;
    } else {
        if(!stun_default_server(&stun_server_addr)) return false;
    }
    
    Addr local = (Addr){.ip="", .port=local_port};
    int sock = make_udp_sock(&local);

    char err_msg[512] = "";
    if(sock < 0) {
        sprintf(err_msg, "[ERR] Couldn't create an UDP socket\n");
        goto error;
    }
    LOG_INFO("[INFO] Created UDP socket\n");
    
    // Make Request
    uint8_t req[STUN_HEADER_LEN] = {0};
    if(!stun_fill_header(req, sizeof(req))) { sprintf(err_msg, "[ERR] Failed to create STUN request"); goto error; }

    struct sockaddr_in server_addr = make_sockaddr_in(stun_server_addr.ip, stun_server_addr.port);
    socklen_t server_addr_len = sizeof(server_addr);

    // Send
    ssize_t bytes_sent = sendto(sock, req, sizeof(req), 0, (struct sockaddr*)&server_addr, server_addr_len);
    if(bytes_sent < STUN_HEADER_LEN) { sprintf(err_msg, "[ERR] Failed to send request to server, bytes sent: %ld", bytes_sent); goto error; }

    // Receive
    uint8_t buffer[STUN_RECV_BUFFER_LEN] = {0};
    ssize_t bytes_read = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&server_addr, &server_addr_len);
    if(bytes_read <= 0) { sprintf(err_msg, "[ERR] No response from server"); goto error; }
    LOG_INFO("[INFO] STUN response received\n");

    // Parse
    STUN_Rsp_Msg rsp = {0};
    if(!stun_parse_rsp(&rsp, buffer, bytes_read)) { sprintf(err_msg, "[ERR] Couldn't parse STUN response"); goto error; }
    LOG_INFO("[INFO] Parsed STUN response successfully\n");

    // Verify
    for(int i = 0; i < STUN_TRANSACTION_ID_LEN; ++i) {
        if(req[8+i] != rsp.id[i]) { sprintf(err_msg, "[ERR] Invalid transaction id received"); goto error; }
    }
    
    // Populate Results
    dest->public_addr = rsp.addr;

    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    if (getsockname(sock, (struct sockaddr *)&sin, &len) == -1)
    { sprintf(err_msg, "[ERR] Couldn't get local IP of the socket"); goto error; }
    strncpy(dest->private_addr.ip, inet_ntoa(sin.sin_addr), sizeof(dest->private_addr.ip)-1);
    dest->private_addr.port = local_port;

    return sock;

error:
    fprintf(stderr, "%s\n", err_msg);
    if(sock >= 0) close(sock);
    return -1;
}

#endif // STUN_IMPLEMENTATION
