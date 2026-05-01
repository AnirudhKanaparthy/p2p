#include <errno.h>
#include <pthread.h> 
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define STUN_IMPLEMENTATION
#include "stun.h"

char* g_peer_name =  NULL;
int g_sock = -1;

void sigint_handler(int) {
    printf("\n\n[INFO] SIGINT received, cleaning resources...\n");

    if(g_sock >=0) close(g_sock);
    printf("[INFO] STUNed socket closed\n");
    
    if(g_peer_name) free(g_peer_name);
    printf("[INFO] Memory freed\n");
    
    exit(0);
}

char* random_name() {
    static const char* nouns[] = {
        "cat",
        "mouse",
        "lion",
        "dolphin",
        "dog",
    };
    static const char* adjs[] = {
        "cunning",
        "baka",
        "sneaky",
        "kind",
        "patriotic",
    };

    size_t rand_noun = (rand() % 5);
    size_t rand_adj = (rand() % 5);

    size_t len_noun = strlen(nouns[rand_noun]);
    size_t len_adj = strlen(adjs[rand_adj]);

    size_t len = 0;
    len += len_noun;
    len += len_adj;
    len += 1 + 1;
    
    char* name = (char*)malloc(len*sizeof(char));
    memset(name, 0, len*sizeof(char));
    
    strncpy(name, adjs[rand_adj], len_adj);
    strncat(name, nouns[rand_noun], len_noun);

    return name;
}

int main(int argc, const char* argv[]) {
    if(argc < 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return -1;
    }
    signal(SIGINT, sigint_handler);
    srand(time(NULL));

    STUN_Addr_Map addr_map = {0};
    int stunned_sock = stun_get_mapping(&addr_map, (uint16_t)atoi(argv[1]), NULL);
    if(stunned_sock < 0) {
        fprintf(stderr, "[ERR] Could not get public address\n");
        return 1;
    }
    g_sock = stunned_sock;

    printf("NAT Mapping: %s:%d -> %s:%d\n",
        addr_map.private_addr.ip, addr_map.private_addr.port,
        addr_map.public_addr.ip,  addr_map.public_addr.port
    );

    printf("Enter peer's address in the form \"<ip>:<port>\": ");

    uint8_t buffer[1024] = {0};
    fgets((char*)buffer, sizeof(buffer), stdin);
    
    size_t i;
    for(i = 0; i < sizeof(buffer); ++i) {
        if(buffer[i] == '\n') break;
        if(buffer[i] == ':')  break;
    }
    if(buffer[i] == '\n') {
        fprintf(stderr, "[ERR] Invalid input, expected \"<ip>:<port>\", but got: %s\n", buffer);
        return 1;
    }
    buffer[i] = '\0';
    uint16_t port = (uint16_t)atoi(((char*)buffer)+i+1);

    Addr peer_addr = (Addr){
        .port=port,
    };
    strncpy(peer_addr.ip, (char*)buffer, i);

    struct sockaddr_in peer_addr_sock = make_sockaddr_in(peer_addr.ip, peer_addr.port);
    socklen_t peer_addr_len = sizeof(peer_addr_sock);
    
    char* peer_name = random_name();
    g_peer_name = peer_name;

    char msg[1024] = {0};
    snprintf(msg, sizeof(msg), "Hello from Peer \"%s\"", peer_name);
    size_t msg_len = strlen(msg);

    for(;;) {
        ssize_t bytes_read = recvfrom(stunned_sock, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr*)&peer_addr_sock, &peer_addr_len);
        if(bytes_read == -1) {
            fprintf(stderr, "[ERR] Failed to receive bytes from peer\n");
        } else {
            buffer[bytes_read] = '\0';
            printf("From peer: %s\n", (char*)buffer);
        }
        ssize_t bytes_sent = sendto(stunned_sock, msg, msg_len, 0, (struct sockaddr*)&peer_addr_sock, peer_addr_len);
        if(bytes_sent == -1) {
            fprintf(stderr, "[ERR] Could not sent message to peer\n");
        } else {
            printf("[INFO] Sent message to peer\n");
        }
        sleep(1);
    }
}
