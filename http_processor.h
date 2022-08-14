#pragma once

#include <stdint.h>

#include "util.h"

enum {
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    HTTP_METHOD_HEAD
};

struct http_header_t
{
    char id[64];
    char value[512];
};

struct http_connection_t
{
    char host[128];
    char **cookies;
    int cookies_num;
};

struct http_request_t
{
    struct http_connection_t *conn;
    struct http_header_t **headers;
    int headers_num;
    int fd;
    char path[256];
    uint8_t method;
};

struct http_request_resp_t
{
    int status;
    char *text_resp;
    int text_resp_len;
};

struct http_connection_t *http_proc_create_conn(char *host);
void http_proc_destroy_conn(struct http_connection_t *conn);//call when ur done running http requests on target
struct http_request_t *http_proc_create_request(struct http_connection_t *conn, uint8_t method, int fd, char *path);
void http_proc_destroy_request(struct http_request_t *req);//call every time request is sent!
void http_proc_req_addhdr(struct http_request_t *req, char *id, char *value);
void http_proc_req_send(struct http_request_t *req, char *data);
struct http_request_resp_t *http_proc_req_parse(struct http_connection_t *conn, char *buffer, int buffer_len);// remeber to free return value!


