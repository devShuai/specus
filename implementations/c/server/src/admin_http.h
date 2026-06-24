#ifndef SHUAI_TUNNEL_ADMIN_HTTP_H
#define SHUAI_TUNNEL_ADMIN_HTTP_H

#include <stddef.h>

typedef struct {
    int port;
    int fd;
    int started;
    char static_root[512];
} st_admin_server;

int st_admin_build_response(const char *method, const char *path, char *out, size_t out_len);
int st_admin_resolve_static_path(const char *static_root,
                                 const char *request_path,
                                 char *file_path,
                                 size_t file_path_len,
                                 const char **content_type);
int st_admin_server_start(st_admin_server *server, int port, const char *static_root);

#endif
