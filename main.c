#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <memory.h>

#define log_line(f_, ...) printf((f_), __VA_ARGS__)

static const int BUFFER_LENGTH = 65536;

#include "dns_utils.h"

int main() {
    const char* REQ = "GET /store HTTP/1.1\r\nAccept: */*\r\nHost: play.google.com\r\n\r\n";

    printf("Running test programme... \n");

    struct sockaddr_in addr;
    get_host_by_name("play.google.com", T_A, &addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);

    size_t size = sizeof(addr);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_line("Failed to open socket at %d\n", __LINE__);
    } else {
        if (connect(sockfd, &addr, size) < 0) {
            log_line("Failed to connect at %d\n", __LINE__);
        } else {
            if (sendto(sockfd, REQ, strlen(REQ), 0, &addr, size) < 0) {
                log_line("Failed to send data at %d\n", __LINE__);
            } else {
                log_line("Sent %s\n", REQ);
                
                char* buffer = malloc(sizeof(char) * BUFFER_LENGTH);
                recvfrom(sockfd, buffer, BUFFER_LENGTH, 0, &addr, &size);

                log_line("Recvd: %s\n", buffer);
            }
        }
    }

    return 0;
}