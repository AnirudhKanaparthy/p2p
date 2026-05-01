#define STUN_IMPLEMENTATION
#include "stun.h"

int main(int argc, const char* argv[]) {
    if(argc < 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return -1;
    }

    STUN_Addr_Map addr_map = {0};
    int stunned_sock = stun_get_mapping(&addr_map, (uint16_t)atoi(argv[1]), NULL);
    if(stunned_sock < 0) {
        fprintf(stderr, "[ERR] Could not get public address\n");
        return 1;
    }
    close(stunned_sock);

    printf("NAT Mapping: %s:%d -> %s:%d\n",
        addr_map.private_addr.ip, addr_map.private_addr.port,
        addr_map.public_addr.ip,  addr_map.public_addr.port
    );
    return 0;
}
