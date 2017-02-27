#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <memory.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <zconf.h>

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
    const SSL_METHOD *method = SSLv23_client_method();
    ERR_load_crypto_strings();
    ERR_load_BIO_strings();
    SSL_load_error_strings();

    struct sockaddr_in addr;
    get_host_by_name((u_char *)HOST, T_A, &addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);

    size_t size = sizeof(addr);

    int err;

    err = SSL_library_init();
    CHK_SSL(err);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_line("Failed to open socket at %d\n", __LINE__);
    } else {
        if (connect(sockfd, &addr, size) < 0) {
            log_line("Failed to connect at %d\n", __LINE__);
        } else {
            SSL_CTX* ctx = SSL_CTX_new (method);
            CHK_NULL(ctx);

            SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, sockfd);

            log_line("Preparing to connect at line %d...\n", __LINE__);

            err = SSL_connect(ssl);

            CHK_SSL(err);
            log_line("SSL connection using %s\n", SSL_get_cipher (ssl));

            // TODO: free-me
            X509* server_cert = SSL_get_peer_certificate(ssl);
            CHK_NULL(server_cert);
            // should probably do some checks here
            X509_free(server_cert);

            err = SSL_write(ssl, request_buffer, strlen(request_buffer));
            CHK_SSL(err);

            char* buffer = malloc(sizeof(char) * BUFFER_LENGTH);
            err = SSL_read(ssl, buffer, BUFFER_LENGTH);
            CHK_SSL(err);

            log_line("Recvd: %s\n", buffer);
            free(buffer);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
        }

        close(sockfd);
    }

    return 0;
}