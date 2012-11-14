#ifndef UDP_REQUEST_H
#define UDP_REQUEST_H

struct context;

int udp_listern_bind(struct context *c);
int udp_listener_start(struct context *c);
void udp_listener_stop(struct context *c);

#endif
