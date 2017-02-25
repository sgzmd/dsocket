#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <memory.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define log_line(f_, ...) printf((f_), __VA_ARGS__)

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }


static const int BUFFER_LENGTH = 65536;
static const char HOST[] = "www.google.co.uk";

#include "dns_utils.h"

int main() {
    const char* REQ = "GET / HTTP/1.1\r\nAccept: */*\r\nHost: %s\r\n\r\n";
    char request_buffer[1024];

    sprintf(request_buffer, REQ, HOST);

    printf("Running test programme... \n");

    OpenSSL_add_ssl_algorithms();
    SSL_METHOD *meth = TLSv1_client_method();
    SSL_load_error_strings();
    SSL_CTX* ctx = SSL_CTX_new (meth);
    CHK_NULL(ctx);

    struct sockaddr_in addr;
    get_host_by_name(HOST, T_A, &addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);

    size_t size = sizeof(addr);

    int err;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_line("Failed to open socket at %d\n", __LINE__);
    } else {
        if (connect(sockfd, &addr, size) < 0) {
            log_line("Failed to connect at %d\n", __LINE__);
        } else {

            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, sockfd);

            err = SSL_connect(ssl);

            CHK_SSL(err);
            log_line("SSL connection using %s\n", SSL_get_cipher (ssl));

            // TODO: free-me
            X509* server_cert = SSL_get_peer_certificate(ssl);
            CHK_NULL(server_cert);
            // should probably do some checks here
            X509_free(server_cert);

            if (sendto(sockfd,
                       request_buffer,
                       strlen(request_buffer),
                       0,
                       &addr,
                       size) < 0) {
                log_line("Failed to send data at %d\n", __LINE__);
            } else {
                log_line("Sent %s\n", request_buffer);
                
                char* buffer = malloc(sizeof(char) * BUFFER_LENGTH);
                recvfrom(sockfd, buffer, BUFFER_LENGTH, 0, &addr, &size);

                log_line("Recvd: %s\n", buffer);
            }
        }
    }

    return 0;
}