#include "admin_http.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    if (strcmp(method, "POST") == 0 && strcmp(path, "/auth/login") == 0) {
        return write_response(out,
                              out_len,
                              200,
                              "OK",
                              "{\"token\":\"local-dev-token\",\"tokenType\":\"Bearer\",\"expiresIn\":28800}");
    }
    return write_response(out, out_len, 404, "Not Found", "{\"error\":\"not found\"}");
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

static void handle_client(int fd)
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
        handle_client(fd);
    }
    return NULL;
}

int st_admin_server_start(st_admin_server *server, int port)
{
    memset(server, 0, sizeof(*server));
    server->port = port;
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
