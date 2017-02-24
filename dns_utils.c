#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/errno.h>
#include <stdbool.h>

#include "dns_utils.h"
#include "dns_internal.h"

#define log_line(f_, ...) printf((f_), __VA_ARGS__)

const u_char GOOGLE_DNS[2][10] = {
        "8.8.8.8",
        "8.8.8.4"
};

#define BUFFER_LENGTH 65536

void host_to_dns_format(
        /* IN */u_char *hostname,
        /* OUT */ u_char *dns) {
    u_char *buffer = (u_char *)
            malloc(sizeof(u_char) * strlen(hostname) + 1);

    strcpy(buffer, hostname);
    strcat(buffer, ".");

    for (int i = 0, j = 0; i < strlen((char *) buffer); i++) {
        if (buffer[i] == '.') {
            *dns++ = i - j;
            for (; j < i; j++) {
                *dns++ = buffer[j];
            }
            j++;
        }
    }

    *dns++ = '\0';

    log_line("Converted %s -> %s\n",
        (const char*) hostname,
        (const char*) dns);

    free(buffer);
}

void get_host_by_name(u_char* host, int query_type, struct sockaddr_in* response) {
    u_char* request_buffer = malloc(
            sizeof(u_char) * BUFFER_LENGTH);

    u_char *response_buffer = malloc(
            sizeof(u_char) * BUFFER_LENGTH);

    log_line("Resolving host %s\n", host);

    struct sockaddr_in dest;
    int dns_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT);
    dest.sin_addr.s_addr = inet_addr(GOOGLE_DNS[0]);

    struct DNS_HEADER *dns = (struct DNS_HEADER*)request_buffer;

    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    // Actual requested hostname will be immediately following the header.
    u_char* question_name;
    question_name = &(request_buffer[sizeof(struct DNS_HEADER)]);
    host_to_dns_format(host, question_name);

    struct QUESTION *question_info;
    question_info = &(request_buffer[sizeof(struct DNS_HEADER)
            + strlen(question_name) + 1]);

    question_info->qclass = htons(1); // Internet
    question_info->qtype = htons(query_type); // A, MX, CNAME, etc

    if (sendto(dns_socket,
               request_buffer,
               sizeof(struct DNS_HEADER) +
                       strlen(question_name) +
                       sizeof(struct QUESTION) + 1,
               0,
               &dest,
               sizeof(dest)) < 0) {
        log_line("Sending request to DNS server failed, errno=%d\n", errno);
    } else {

        int sockaddr_len = sizeof(struct sockaddr_in);
        int recvd = recvfrom(dns_socket,
                             response_buffer,
                             BUFFER_LENGTH,
                             0,
                             &dest,
                             &sockaddr_len);

        if (recvd < 0) {
            log_line("Failed to receive from socket, errno=%d", errno);
        } else {
            log_line("Received %d bytes from socket", recvd);

            FILE* f = fopen("test.bin", "wb");
            fwrite(response_buffer, BUFFER_LENGTH, 1, f);
            fclose(f);

            dns = (struct DNS_HEADER*) response_buffer;

            log_line("Response contains: questions=%d, answers=%d, auth servers=%d, addl records=%d\n",
                     ntohs(dns->q_count),
                     ntohs(dns->ans_count),
                     ntohs(dns->auth_count),
                     ntohs(dns->add_count));

            u_char* reader = NULL;
            reader = response_buffer +
                    sizeof(struct DNS_HEADER) +
                    strlen(question_name) + 1 +
                    sizeof(struct QUESTION);

            struct RES_RECORD answers[20];

            int stop = 0;
            for (int i = 0; i < ntohs(dns->ans_count); i++) {
                // TODO: free-me
                answers[i].name = read_name(reader, response_buffer, &stop);
                reader += stop;

                answers[i].resource = (struct R_DATA*) reader;
                reader += sizeof(struct R_DATA);

                // Is this an IPv4 address?
                if (ntohs(answers[i].resource->type) == T_A) {
                    unsigned res_data_len = ntohs(answers[i].resource->data_len);

                    // TODO: free-me
                    answers[i].rdata = (u_char*) malloc(res_data_len);

                    for (int j = 0; j < res_data_len; ++j) {
                        answers[i].rdata[j] = reader[j];
                    }

                    answers[i].rdata[res_data_len] = 0;
                    reader += res_data_len;

                    long* p = (long*) answers[i].rdata;
                    response->sin_addr.s_addr = *p;
                    log_line("%s resolved to  %s\n",
                             answers[i].name,
                             inet_ntoa(response->sin_addr));
                } else {
                    // TODO: free-me
                    answers[i].rdata = read_name(reader, response_buffer, &stop);
                    reader += stop;
                }
            }

            for (int i = 0; i < ntohs(dns->ans_count); ++i) {
                free(answers[i].name);
                free(answers[i].rdata);
            }
        }
    }

    free(request_buffer);
    free(response_buffer);
}

u_char * read_name(u_char* reader, u_char* buffer, int* count) {
    u_char* name = (u_char*) malloc(256);;
    uint p = 0, offset = 0;
    bool jumped = false;

    *count = 1;
    name[0] = 0;

    while (*reader != 0) {
        if (*reader >= 192) {
            // TODO: understand why it works that way. Yes this does
            // add up, checked in hex viewer of the response, but why?
            offset = (*reader)*256 + *(reader+1) - 49152;
            reader = buffer + offset - 1;
            jumped = true;
        } else {
            name[p++] = *reader;
        }

        ++reader;
        if (!jumped) {
            *count = *count + 1;
        }
    }

    name[p] = 0;
    if (jumped) {
        //number of steps we actually moved forward in the packet
        *count = *count + 1;
    }

    // Now the name should be \0x3www\0x6google\0x3com
    int i = 0;
    for ( ; i < strlen(name); ++i) {
        // We always start with the \0x3 part
        p = name[i];
        for (int j = 0; j < p; ++j, ++i) {
            // Moving 'www' one position left
            name[i] = name[i+1];
        }
        name[i] = '.';
    }

    // Remove the last dot
    name[i-1] = '\0';

    return name;
}