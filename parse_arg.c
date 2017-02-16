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
    if (strstr (arg, "tcp:") == arg) {
        char *tmp;

        *type = SOCKET_TCP;

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

        *port = (uint16_t) atoi ((const char *) *port_str);
        memset (sin, 0, sizeof (struct sockaddr_in));
        sin->sin_addr.s_addr = inet_addr (*host_str);
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
                    /* TODO prerobit na warning */
                    perror ("unlink");
                    _exit (-1);
                }
            }
        }
        *socklen = sizeof (struct sockaddr_un);
    }
}
