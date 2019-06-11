#include "rum.h"

/* arg - in (tcp:blah:blah or sock:blah)
 * all other - out (we fill it)
 */
void
parse_arg (char *arg, char *type, struct sockaddr_in *sin,
           struct sockaddr_un *sun, socklen_t * socklen, uint16_t * port,
           char **host_str, char **port_str, char **sockfile_str,
           int unlink_socket)
{
    if (strstr (arg, "tcp:") == arg || strstr (arg, "ssl:") == arg) {
        char *tmp;
        int resolv = 0;

        if (strstr (arg, "tcp:") == arg) {
            *type = SOCKET_TCP;
        } else {
            *type = SOCKET_SSL;
            /* overwrite ssl to Ssl */
            arg[0] = 'S';
        }

        arg += 4;
        tmp = strstr (arg, ":");
        if (tmp != NULL) {
            *host_str = arg;
            *tmp = '\0';
            tmp++;
            *port_str = tmp;
        } else {
            usage ();
        }

        if (!strcmp(*host_str, "localhost")) {
            *host_str="127.0.0.1";
        }

        for (tmp = *host_str; *tmp; tmp++) {
            if (isalpha(*tmp)) {
                /* resolv host_str to ip */
                resolv = 1;
                break;
            }
        }


        *port = (uint16_t) atoi ((const char *) *port_str);
        memset (sin, 0, sizeof (struct sockaddr_in));
        if (resolv) {
            sin->sin_addr.s_addr = resolv_host_to_ip(*host_str);
        } else {
            sin->sin_addr.s_addr = inet_addr (*host_str);
        }
        sin->sin_port = htons (*port);
        sin->sin_family = AF_INET;

        *socklen = sizeof (struct sockaddr_in);
    } else if (strstr (arg, "sock:") == arg) {
        arg += 5;
        *sockfile_str = arg;

        *type = SOCKET_UNIX;

        memset (sun, 0, sizeof (struct sockaddr_un));
        sun->sun_family = AF_UNIX;
        memcpy (sun->sun_path, *sockfile_str, strlen (*sockfile_str));

        if (unlink_socket) {
            if (!access (*sockfile_str, F_OK)) {
                if (unlink (*sockfile_str)) {
                    perror ("unlink");
                    _exit (-1);
                }
            }
        }
        *socklen = sizeof (struct sockaddr_un);
    }
}

in_addr_t resolv_host_to_ip(char *host) {
    /* resolv host_str to ip */
    int s;
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    in_addr_t ip = 0;
    struct sockaddr_in *h;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    s = getaddrinfo(host, NULL, &hints, &result);
    if (s != 0) {
        logmsg("error: getaddrinfo: %s (%s)", gai_strerror(s), host);
        _exit(-1);
    }

    for(rp = result; rp != NULL; rp = rp->ai_next) 
    {
          h = (struct sockaddr_in *) rp->ai_addr;
          ip = h->sin_addr.s_addr;
          break;
    }

    freeaddrinfo (result);

    return ip;
}
