//
// Created by Roman Kirillov on 24/02/2017.
//


/*
 * This is a remake of gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
 * by Silver Moon (m00n.silv3r@gmail.com)
 */

#ifndef DSOCKET_DNS_UTILS_H
#define DSOCKET_DNS_UTILS_H

/**
 * Converts hostname such as www.google.com to DNS format,
 * \0x3www\0x6google\0x3com
 *
 * @param hostname Name of the host, such as google.com
 * @param dns DNS-format host.
 *
 * It is callers responsibility to ensure dns is big enough.
 */
void host_to_dns_format(
        /* IN */unsigned char *hostname,
        /* OUT */ unsigned char *dns);

/**
 * Obtains DNS data in TBD format
 *
 * @param host
 * @param query_type
 */
void get_host_by_name(unsigned char* host, int query_type, struct sockaddr_in* response);

#ifndef log_line
#define log_line(f_, ...) printf((f_), __VA_ARGS__)
#endif

#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server


#endif //DSOCKET_DNS_UTILS_H
