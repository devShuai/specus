#include "admin_http.h"

#include "security.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>

static int write_response(char *out, size_t out_len, int status, const char *reason, const char *body)
{
    if (body == NULL) {
        body = "";
    }
    int written = snprintf(out,
                           out_len,
                           "HTTP/1.1 %d %s\r\n"
                           "Content-Type: application/json\r\n"
                           "Cache-Control: no-store\r\n"
                           "X-Content-Type-Options: nosniff\r\n"
                           "Content-Length: %zu\r\n"
                           "\r\n"
                           "%s",
                           status,
                           reason,
                           strlen(body),
                           body);
    return written < 0 || (size_t)written >= out_len ? -1 : written;
}

int st_admin_build_response(const char *method, const char *path, char *out, size_t out_len)
{
    if (method == NULL || path == NULL) {
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"bad request\"}");
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/health") == 0) {
        return write_response(out, out_len, 200, "OK", "{\"status\":\"ok\"}");
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/admin/overview") == 0) {
        return write_response(out,
                              out_len,
                              200,
                              "OK",
                              "{\"server\":\"c\",\"status\":\"ok\",\"onlineClients\":0,\"tcpMappings\":0}");
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/admin/metrics") == 0) {
        return write_response(out,
                              out_len,
                              200,
                              "OK",
                              "{\"server\":\"c\",\"metricsWired\":false,"
                              "\"onlineClients\":0,\"listeners\":0,\"externalConnections\":0}");
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/auth/login") == 0) {
        return write_response(out,
                              out_len,
                              200,
                              "OK",
                              "{\"token\":\"local-dev-token\",\"tokenType\":\"Bearer\",\"expiresIn\":28800}");
    }
    if (strncmp(path, "/http/", 6) == 0) {
        return write_response(out,
                              out_len,
                              501,
                              "Not Implemented",
                              "{\"error\":\"direct http dispatch is not wired yet\"}");
    }
    if (strcmp(path, "/ws/connections") == 0) {
        return write_response(out,
                              out_len,
                              426,
                              "Upgrade Required",
                              "{\"error\":\"websocket connection events are not wired yet\"}");
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/oidc-config") == 0) {
        char body[1024];
        if (st_security_build_oidc_config(getenv("TUNNEL_OIDC_CLIENT_ID"),
                                          getenv("TUNNEL_OIDC_AUTHORIZATION_ENDPOINT"),
                                          getenv("TUNNEL_OIDC_TOKEN_ENDPOINT"),
                                          getenv("TUNNEL_OIDC_ISSUER"),
                                          body,
                                          sizeof(body)) < 0) {
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"oidc config failed\"}");
        }
        return write_response(out, out_len, 200, "OK", body);
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/oidc/token") == 0) {
        return write_response(out,
                              out_len,
                              501,
                              "Not Implemented",
                              "{\"error\":\"oidc token exchange is not wired yet\"}");
    }
    return write_response(out, out_len, 404, "Not Found", "{\"error\":\"not found\"}");
}

int st_admin_resolve_static_path(const char *static_root,
                                 const char *request_path,
                                 char *file_path,
                                 size_t file_path_len,
                                 const char **content_type)
{
    if (static_root == NULL || *static_root == '\0'
        || request_path == NULL || request_path[0] != '/'
        || strstr(request_path, "..") != NULL) {
        return -1;
    }
    const char *relative = request_path[1] == '\0' ? "index.html" : request_path + 1;
    const char *query = strchr(relative, '?');
    size_t relative_len = query == NULL ? strlen(relative) : (size_t)(query - relative);
    if (relative_len == 0) {
        relative = "index.html";
        relative_len = strlen(relative);
    }
    int written = snprintf(file_path, file_path_len, "%s/%.*s", static_root, (int)relative_len, relative);
    if (written < 0 || (size_t)written >= file_path_len) {
        return -1;
    }
    const char *dot = strrchr(file_path, '.');
    if (dot != NULL && strcmp(dot, ".html") == 0) {
        *content_type = "text/html; charset=utf-8";
    } else if (dot != NULL && strcmp(dot, ".js") == 0) {
        *content_type = "application/javascript; charset=utf-8";
    } else if (dot != NULL && strcmp(dot, ".css") == 0) {
        *content_type = "text/css; charset=utf-8";
    } else {
        *content_type = "application/octet-stream";
    }
    return 0;
}

static int send_all(int fd, const char *buffer, size_t len)
{
    size_t offset = 0;
    while (offset < len) {
        ssize_t sent = send(fd, buffer + offset, len - offset, 0);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        offset += (size_t)sent;
    }
    return 0;
}

static int send_static_file(int fd, const char *method, const char *path, const char *static_root)
{
    if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0) {
        return 0;
    }
    char file_path[1024];
    const char *content_type = NULL;
    if (st_admin_resolve_static_path(static_root, path, file_path, sizeof(file_path), &content_type) != 0) {
        return 0;
    }
    struct stat st;
    if (stat(file_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return 0;
    }
    FILE *file = fopen(file_path, "rb");
    if (file == NULL) {
        return 0;
    }
    char header[512];
    int header_len = snprintf(header,
                              sizeof(header),
                              "HTTP/1.1 200 OK\r\n"
                              "Content-Type: %s\r\n"
                              "Cache-Control: no-cache\r\n"
                              "X-Content-Type-Options: nosniff\r\n"
                              "Content-Length: %lld\r\n"
                              "\r\n",
                              content_type,
                              (long long)st.st_size);
    if (header_len <= 0 || (size_t)header_len >= sizeof(header)
        || send_all(fd, header, (size_t)header_len) != 0) {
        fclose(file);
        return 1;
    }
    if (strcmp(method, "HEAD") != 0) {
        char buffer[8192];
        size_t read_len;
        while ((read_len = fread(buffer, 1, sizeof(buffer), file)) > 0) {
            if (send_all(fd, buffer, read_len) != 0) {
                break;
            }
        }
    }
    fclose(file);
    return 1;
}

static void handle_client(st_admin_server *server, int fd)
{
    char request[8192];
    ssize_t len = recv(fd, request, sizeof(request) - 1U, 0);
    if (len <= 0) {
        close(fd);
        return;
    }
    request[len] = '\0';
    char method[16] = {0};
    char path[1024] = {0};
    if (sscanf(request, "%15s %1023s", method, path) != 2) {
        strcpy(method, "");
        strcpy(path, "");
    }
    if (send_static_file(fd, method, path, server->static_root)) {
        close(fd);
        return;
    }
    char response[4096];
    int response_len = st_admin_build_response(method, path, response, sizeof(response));
    if (response_len > 0) {
        send_all(fd, response, (size_t)response_len);
    }
    close(fd);
}

static void *admin_thread(void *arg)
{
    st_admin_server *server = (st_admin_server *)arg;
    printf("[admin] listening on 0.0.0.0:%d\n", server->port);
    for (;;) {
        int fd = accept(server->fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        handle_client(server, fd);
    }
    return NULL;
}

int st_admin_server_start(st_admin_server *server, int port, const char *static_root)
{
    memset(server, 0, sizeof(*server));
    server->port = port;
    snprintf(server->static_root, sizeof(server->static_root), "%s", static_root == NULL ? "" : static_root);
    server->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->fd < 0) {
        perror("admin socket");
        return -1;
    }
    int yes = 1;
    setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);
    if (bind(server->fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("admin bind");
        close(server->fd);
        server->fd = -1;
        return -1;
    }
    if (listen(server->fd, 64) != 0) {
        perror("admin listen");
        close(server->fd);
        server->fd = -1;
        return -1;
    }

    pthread_t thread;
    if (pthread_create(&thread, NULL, admin_thread, server) != 0) {
        perror("admin pthread_create");
        close(server->fd);
        server->fd = -1;
        return -1;
    }
    pthread_detach(thread);
    server->started = 1;
    return 0;
}
