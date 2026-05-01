#ifndef NET_H_
#define NET_H_

#include <stdint.h>
#include <arpa/inet.h>

typedef struct {
    char ip[16];
    uint16_t port;
} Addr;

typedef struct {
    Addr        connect_addr;
    const Addr* bind_addr;
    int         protocol;  // TODO: This is a bad name
} Sock_Conf;

// Allocates memory
char* resolve_domain(const char* domain);
struct sockaddr_in make_sockaddr_in(const char* ip, uint16_t port);

int conf_connect_impl(const Sock_Conf conf);
#define conf_connect(...) conf_connect_impl((Sock_Conf){ .bind_addr=NULL, .protocol=SOCK_STREAM, __VA_ARGS__})
#define make_tcp_sock(...) conf_connect(__VA_ARGS__, .protocol=SOCK_STREAM)

int make_udp_sock(const Addr* bind_addr);

#endif // NET_H_

#ifdef NET_IMPLEMENTATION

#include <netdb.h>
#include <string.h>
#include <unistd.h>

// Allocates memory
char* resolve_domain(const char* domain) {
    if(!domain) return NULL;
    struct hostent *host_info = gethostbyname(domain); // Returns a static pointer
    if(!host_info) return NULL;

    struct in_addr *addr = (struct in_addr *)(host_info->h_addr_list[0]);
    const char* ip = inet_ntoa(*addr); // Returns a static pointer
    return strdup(ip);
}

struct sockaddr_in make_sockaddr_in(const char* ip, uint16_t port) {
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = (!ip || strlen(ip) == 0) ? 0 : inet_addr(ip);
    addr.sin_port = htons(port);
    return addr;
}

int conf_connect_impl(const Sock_Conf conf) {
    if(!conf.connect_addr.port || !conf.protocol) return -1;
    int sock = socket(AF_INET, conf.protocol, 0);

    if(conf.bind_addr) {
        if(!conf.bind_addr->port || !conf.protocol) { close(sock); return -1; }
        struct sockaddr_in localaddr = make_sockaddr_in(conf.bind_addr->ip, conf.bind_addr->port);
        if(bind(sock, (struct sockaddr *)&localaddr, sizeof(localaddr)) != 0) { close(sock); return -1; }
    }

    struct sockaddr_in saddr = make_sockaddr_in(conf.connect_addr.ip, conf.connect_addr.port);
    int status = connect(sock, (struct sockaddr *)&saddr, sizeof(saddr));
    if(status < 0) { close(sock); return -1; }
    return sock;
}

int make_udp_sock(const Addr* bind_addr) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) return sock;
    if(bind_addr) {
        if(!bind_addr->port) { close(sock); return -1; }
        struct sockaddr_in localaddr = make_sockaddr_in(bind_addr->ip, bind_addr->port);
        if(bind(sock, (struct sockaddr *)&localaddr, sizeof(localaddr)) != 0) { close(sock); return -1; }
    }
    return sock;
}

#endif // NET_IMPLEMENTATION