#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

#include "http_processor.h"
#include "util.h"


static uint8_t parse_cookie(char **out, char *buffer, int buffer_len);
static int parse_status(char *buffer, int buffer_len); 

struct http_connection_t *http_proc_create_conn(char *host)
{
    struct http_connection_t *conn = malloc(sizeof(struct http_connection_t));
    memset(conn, 0, sizeof(struct http_connection_t));
    strcpy(conn->host, host);
    conn->cookies = NULL;
    conn->cookies_num = 0;
    return conn;
}

void http_proc_destroy_conn(struct http_connection_t *conn)
{
    if(conn != NULL)
    {
        int j;
        for(j = 0; j < conn->cookies_num; j++)
        {
             free(conn->cookies[j]);
        }
        free(conn->cookies);
        memset(conn, 0, sizeof(struct http_connection_t));
        free(conn);
    }
}

struct http_request_t *http_proc_create_request(struct http_connection_t *conn, uint8_t method, int fd, char *path)
{
    struct http_request_t *req = malloc(sizeof(struct http_request_t));
    memset(req, 0, sizeof(struct http_request_t));
    req->conn = conn;
    req->headers = malloc(1*sizeof(struct http_header_t *));
    req->headers[0] = malloc(sizeof(struct http_header_t));
    memset(req->headers[0], 0, sizeof(struct http_header_t));
    strcpy(req->headers[0]->id, "Host");
    strcpy(req->headers[0]->value, conn->host);
    strcpy(req->path, path);
    req->headers_num = 1;
    req->method = method;
    req->fd = fd;
}

void http_proc_destroy_request(struct http_request_t *req)
{
    if(req != NULL)
    {
        int j;
        for(j = 0; j < req->headers_num; j++)
        {
            free(req->headers[j]);
        }
        free(req->headers);
        req->conn = NULL;
        memset(req, 0, sizeof(struct http_request_t));
        free(req);
    }    
}

void http_proc_req_addhdr(struct http_request_t *req, char *id, char *value)
{
    req->headers = realloc(req->headers, (req->headers_num+1)*sizeof(struct http_header_t *));
    req->headers[req->headers_num] = malloc(sizeof(struct http_header_t));
    memset(req->headers[req->headers_num], 0, sizeof(struct http_header_t));
    strcpy(req->headers[req->headers_num]->id, id);
    strcpy(req->headers[req->headers_num]->value, value);
    req->headers_num += 1;
    return;
}

void http_proc_req_send(struct http_request_t *req, char *data)
{
    char sendbuffer[4096];
    memset(sendbuffer, 0, 4096);
    
    switch(req->method)
    {
        case HTTP_METHOD_GET:
            sprintf(sendbuffer, "GET %s HTTP/1.1\r\n", req->path);
            break;
        case HTTP_METHOD_POST:
            sprintf(sendbuffer, "POST %s HTTP/1.1\r\n", req->path);
            break;
        case HTTP_METHOD_HEAD:
            sprintf(sendbuffer, "HEAD %s HTTP/1.1\r\n", req->path);
            break;
    }
    
    int j;
    for(j = 0; j < req->headers_num; j++)
    {
        int sendbuffer_len = strlen(sendbuffer);
        strcpy(sendbuffer+sendbuffer_len, req->headers[j]->id);
        sendbuffer_len = strlen(sendbuffer);
        strcpy(sendbuffer+sendbuffer_len, ": ");
        sendbuffer_len = strlen(sendbuffer);
        strcpy(sendbuffer+sendbuffer_len, req->headers[j]->value);
        sendbuffer_len = strlen(sendbuffer);
        strcpy(sendbuffer+sendbuffer_len, "\r\n");
    }
    
    if(req->conn->cookies_num > 0)
    {
        char cookie_hdr[512];
        int cookie_hdr_len = 0;
        sprintf(cookie_hdr, "Cookie: ");
        for(j = 0; j < req->conn->cookies_num; j++)
        {
            cookie_hdr_len = strlen(cookie_hdr);
            if(j == req->conn->cookies_num-1)
            {
                sprintf(cookie_hdr+cookie_hdr_len, "%s\r\n", req->conn->cookies[j]);
                break;
            }
            sprintf(cookie_hdr+cookie_hdr_len, "%s; ", req->conn->cookies[j]);
        }
        int sendbuffer_len = strlen(sendbuffer);
        sprintf(sendbuffer+sendbuffer_len, "%s", cookie_hdr);
    }
    else
    {   // some implementations of digest auth demand there be a cookie even though we werent given one ;)
        int sendbuffer_len = strlen(sendbuffer);
        sprintf(sendbuffer+sendbuffer_len, "Cookie: fake=fake_value\r\n");
    }
    
    int sendbuffer_len = strlen(sendbuffer);
    sprintf(sendbuffer+sendbuffer_len, "\r\n");
    sendbuffer_len = strlen(sendbuffer);
    if(data != NULL)
    {
        sprintf(sendbuffer+sendbuffer_len, "%s\r\n", data);
    }
    
    #ifdef DEBUG_HTTP
          printf("[http_processor] Sending the following request:\r\n");
          printf("-----------------------------------------------------\r\n");
          printf("%s\r\n", sendbuffer);
          printf("-----------------------------------------------------\r\n");
    #endif
    
    send(req->fd, sendbuffer, 4096, MSG_NOSIGNAL);
    
    return;
}

struct http_request_resp_t *http_proc_req_parse(struct http_connection_t *conn, char *buffer, int buffer_len)
{
    struct http_request_resp_t *resp = malloc(sizeof(struct http_request_resp_t));
    memset(resp, 0, sizeof(struct http_request_resp_t));
    resp->status = parse_status(buffer, buffer_len);
    resp->text_resp = buffer;
    resp->text_resp_len = buffer_len;
    conn->cookies_num = parse_cookie(conn->cookies, buffer, buffer_len);
    return resp;
}



static int parse_status(char *buffer, int buffer_len)
{
    int ret = -1;
    int j = 0, line_len = 0;
    char line[1024];
    memset(line, 0, 1024);
    for(j = 0; j < buffer_len; j++)
    {
        if(buffer[j] == '\r')
        {
            continue;
        }
        if(buffer[j] == '\n')
        {
            if(strstr(line, "HTTP") != NULL)
            {
                ret = atoi(line+strlen("HTTP/1.1 "));
            }
            memset(line, 0, 512);
            line_len = 0;
            break;
        }
        line[line_len] = buffer[j];
        line_len++;
    }
    
    printf("Got resp code %d!\r\n", ret);
    return ret;
}

static uint8_t parse_cookie(char **out, char *buffer, int buffer_len)
{
    uint8_t ret = 0;
    int j = 0, line_len = 0;
    char line[1024];
    char lastfour[4];
    memset(lastfour, 0, 4);
    memset(line, 0, 1024);
    for(j = 0; j < buffer_len; j++)
    {
        lastfour[0] = lastfour[1];
        lastfour[1] = lastfour[2];
        lastfour[2] = lastfour[3];
        lastfour[3] = buffer[j];
        if(lastfour[0] == '\r' && lastfour[1] == '\n' && lastfour[2] == '\r' && lastfour[3] == '\n')
        {
                break;
        }
        if(buffer[j] == '\r')
        {
                continue;
        }
        if(buffer[j] == '\n')
        {
            if(strstr(line, "Set-Cookie: ") != NULL)
            {
                char *cookies_ptr = line+strlen("Set-Cookie: ");
                // server wants us to save data in client session
                int cookies_count = 0;
                uint8_t **cookies = util_tokenize(cookies_ptr, line_len-strlen("Set-Cookie: "), &cookies_count, ',');
                int i;
                for(i = 0; i < cookies_count; i++)
                {
                    if((cookies[i])[0] == ' ')
                    {
                        memcpy(cookies[i], (cookies[i])+1, strlen(cookies[i])-1);
                        (cookies[i])[strlen(cookies[i])-1] = 0;
                    }
                    int cookie_attr_count = 0;
                    uint8_t **cookie_attr = util_tokenize(cookies[i], util_len(cookies[i]), &cookie_attr_count, ';');
                    if(cookie_attr_count > 0)
                    {
                        out = realloc(out, (ret+1)*sizeof(char *));
                        out[ret] = malloc(strlen(cookie_attr[0]));
                        util_cpy(out[ret], cookie_attr[0], strlen(cookie_attr[0]));
                        ret++;
                    }
                }
            }
            memset(line, 0, 512);
            line_len = 0;
            continue;
        }
        line[line_len] = buffer[j];
        line_len++;
    }
    
    printf("Got %d cookies!\r\n", ret);
    for(j = 0; j < ret; j++)
    {
         printf("Cookie %d ~> \"%s\"\r\n", j, out[j]);
    }
    return ret;
}



