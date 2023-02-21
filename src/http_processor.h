#pragma once

#include <stdint.h>

#include "util.h"

enum {
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    HTTP_METHOD_HEAD
};

struct http_auth_t
{
    char username[64];
    char password[128];
};

struct http_header_t
{
    char id[64];
    char value[512];
};

struct http_connection_t
{
    char host[128];
    char curr_path[256];
    int cookies_num;
    int auth_credentials_len;
    int auth_credentials_pos;
    uint8_t curr_method;
    struct http_auth_t **auth_credentials;
    char **cookies;
    char *auth_hdr;
    struct http_request_resp_t *last_resp;
};

struct http_request_t
{
    struct http_connection_t *conn;
    struct http_header_t **headers;
    int headers_num;
    int fd;
    char *path;
    uint8_t method;
};

struct http_request_resp_t
{
    int status;
    char *text_resp;
    int text_resp_len;
    int again;
};

char *md5_calchash(char *string);

void base64_load();
void base64_unload();
char *base64_encode(const unsigned char *data, int input_length, int *output_length);
unsigned char *base64_decode(const char *data, int input_length, int *output_length);

void http_proc_load();
char *http_proc_url_encode(unsigned char *s, char *enc);

struct http_connection_t *http_proc_create_conn(char *host);
void http_proc_destroy_conn(struct http_connection_t *conn);//call when ur done running http requests on target
void http_proc_conn_addauth(struct http_connection_t *conn, char *username, char *password);

struct http_request_t *http_proc_create_request(struct http_connection_t *conn, uint8_t method, int fd, char *path);
void http_proc_destroy_request(struct http_request_t *req);//call every time request is sent!
void http_proc_req_addhdr(struct http_request_t *req, char *id, char *value);
void http_proc_req_send_(struct http_request_t *req, char *data, int data_size);
void http_proc_req_send(struct http_request_t *req, char *data);
struct http_request_resp_t *http_proc_req_parse(struct http_connection_t *conn, char *buffer, int buffer_len);// remeber to free return value!


