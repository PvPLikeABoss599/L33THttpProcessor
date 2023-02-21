#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <bsd/md5.h>

#include "http_processor.h"
#include "digcalc.h"
#include "util.h"


static char *parse_digest_auth(struct http_connection_t *conn, char *buffer, int buffer_len);
static uint8_t parse_cookie(struct http_connection_t *conn, char *buffer, int buffer_len);
static int parse_status(char *buffer, int buffer_len); 

char rfc3986[256] = {0};
char html5[256] = {0};

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};

char *md5_calchash(char *string)
{
    MD5_CTX Md5Ctx;
    char *ret = malloc(16);
    if(ret == NULL) return NULL;
    memset(ret, 0, 16);

    MD5Init(&Md5Ctx);
    MD5Update(&Md5Ctx, string, strlen(string));
    MD5Final(ret, &Md5Ctx);
    
    return ret;
}

void base64_load() 
{

    decoding_table = malloc(256);
    memset(decoding_table, 0, 256);
    
    int i;
    
    for (i = 0; i < 64; i++)
        decoding_table[(uint8_t) encoding_table[i]] = i;
    
    return;
}


void base64_unload() 
{
    memset(decoding_table, 0, 256);
    free(decoding_table);
    decoding_table = NULL;
    return;
}

char *base64_encode(const unsigned char *data, int input_length, int *output_length) 
{
    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length);
    
    if (encoded_data == NULL) { return NULL; }
    
    memset(encoded_data, 0, *output_length);
    int i, j;
    
    for (i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}


unsigned char *base64_decode(const char *data, int input_length, int *output_length) {
    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;
    memset(decoded_data, 0, *output_length);
    
    int i, j;
    
    for (i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}

void http_proc_load()
{

    int i;

    for (i = 0; i < 256; i++){

        rfc3986[i] = isalnum( i) || i == '~' || i == '-' || i == '.' || i == '_' ? i : 0;
        html5[i] = isalnum( i) || i == '*' || i == '-' || i == '.' || i == '_' ? i : (i == ' ') ? '+' : 0;
    }
}

char *http_proc_url_encode(unsigned char *s, char *enc)
{
    for (; *s; s++) 
    {
        if (html5[*s]) *enc = html5[*s];
        else sprintf(enc, "%%%02X", *s);
        while (*++enc);
    }

    return(enc);
}

struct http_connection_t *http_proc_create_conn(char *host)
{
    struct http_connection_t *conn = malloc(sizeof(struct http_connection_t));
    memset(conn, 0, sizeof(struct http_connection_t));
    memset(conn->host, 0, sizeof(conn->host));
    strcpy(conn->host, host);
    memset(conn->curr_path, 0, sizeof(conn->curr_path));
    conn->cookies = NULL;
    conn->cookies_num = 0;
    conn->auth_hdr = NULL;
    conn->auth_credentials = NULL;
    conn->auth_credentials_len = 0;
    conn->auth_credentials_pos = 0;
    return conn;
}

void http_proc_destroy_conn(struct http_connection_t *conn)
{
    if(conn != NULL)
    {
        if(conn->last_resp != NULL)
        {
            if(conn->last_resp->text_resp != NULL)
            {
                free(conn->last_resp->text_resp);
                conn->last_resp->text_resp = NULL;
            }
            free(conn->last_resp);
            conn->last_resp = NULL;
        }
        
        if(conn->auth_hdr != NULL)
        {
            free(conn->auth_hdr);
            conn->auth_hdr = NULL;
        }
        int j;
        
        if(conn->cookies != NULL)
        {
            for(j = 0; j < conn->cookies_num; j++)
            {
                free(conn->cookies[j]);
                conn->cookies[j] = NULL;
            }
            free(conn->cookies);
            conn->cookies = NULL;
        }
        
        if(conn->auth_credentials != NULL)
        {
            for(j = 0; j < conn->auth_credentials_len; j++)
            {
                free(conn->auth_credentials[j]);
                conn->auth_credentials[j] = NULL;
            }
            free(conn->auth_credentials);
            conn->auth_credentials = NULL;
        }
        
        
        memset(conn, 0, sizeof(struct http_connection_t));
        free(conn);
        conn = NULL;
    }
}

void http_proc_conn_addauth(struct http_connection_t *conn, char *username, char *password)
{
    struct http_auth_t *auth = NULL;
    conn->auth_credentials = realloc(conn->auth_credentials, (conn->auth_credentials_len+1)*sizeof(struct http_auth_t *));
    conn->auth_credentials[conn->auth_credentials_len] = malloc(sizeof(struct http_auth_t));
    auth = conn->auth_credentials[conn->auth_credentials_len];
    memset(auth, 0, sizeof(struct http_auth_t));
    conn->auth_credentials_len++;
    
    strncpy(auth->username, username, sizeof(auth->username));
    strncpy(auth->password, password, sizeof(auth->password));
}

struct http_request_t *http_proc_create_request(struct http_connection_t *conn, uint8_t method, int fd, char *path)
{
    strncpy(conn->curr_path, path, sizeof(conn->curr_path));
    conn->curr_method = method;
    
    struct http_request_t *req = malloc(sizeof(struct http_request_t));
    memset(req, 0, sizeof(struct http_request_t));
    req->conn = conn;
    req->headers = malloc(1*sizeof(struct http_header_t *));
    req->headers[0] = malloc(sizeof(struct http_header_t));
    memset(req->headers[0], 0, sizeof(struct http_header_t));
    strcpy(req->headers[0]->id, "Host");
    strcpy(req->headers[0]->value, conn->host);
    req->path = conn->curr_path;
    req->headers_num = 1;
    req->method = conn->curr_method;
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

void http_proc_req_send_(struct http_request_t *req, char *data, int data_size)
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
    
    if(req->conn->auth_hdr != NULL)
    {
        int sendbuffer_len = strlen(sendbuffer);
        strcpy(sendbuffer+sendbuffer_len, req->conn->auth_hdr);
        sendbuffer_len = strlen(sendbuffer);
        strcpy(sendbuffer+sendbuffer_len, "\r\n");
        free(req->conn->auth_hdr);
        req->conn->auth_hdr = NULL;
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
    
    if(data != NULL)
    {
        sendbuffer_len = strlen(sendbuffer);
        memcpy(sendbuffer+sendbuffer_len, data, data_size);
        memcpy(sendbuffer+sendbuffer_len+data_size, "\r\n", 2);
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
    
    if(req->conn->auth_hdr != NULL)
    {
        int sendbuffer_len = strlen(sendbuffer);
        strcpy(sendbuffer+sendbuffer_len, req->conn->auth_hdr);
        sendbuffer_len = strlen(sendbuffer);
        strcpy(sendbuffer+sendbuffer_len, "\r\n");
        free(req->conn->auth_hdr);
        req->conn->auth_hdr = NULL;
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
    resp->text_resp = malloc(buffer_len+1);
    memset(resp->text_resp, 0, buffer_len+1);
    strncpy(resp->text_resp, buffer, buffer_len);
    resp->text_resp_len = buffer_len;
    resp->again = 0;
    
    parse_cookie(conn, buffer, buffer_len);
    
    // check if we have credentials to give website
    char *tmp_auth_hdr = parse_digest_auth(conn, buffer, buffer_len);
    if(tmp_auth_hdr != NULL)
    {
        if(conn->auth_hdr != NULL)
        {
            free(conn->auth_hdr);
            conn->auth_hdr = NULL;
        }
        conn->auth_hdr = tmp_auth_hdr;
        resp->again = 1;
    }
    
    if(conn->last_resp != NULL)
    {
        if(conn->last_resp->text_resp != NULL)
        {
            free(conn->last_resp->text_resp);
            conn->last_resp->text_resp = NULL;
        }
        free(conn->last_resp);
        conn->last_resp = NULL;
    }
    
    conn->last_resp = resp;
    
    return resp;
}


static char *parse_digest_auth(struct http_connection_t *conn, char *buffer, int buffer_len)
{
    
    if(conn->auth_credentials_len == 0) return NULL;
    if(conn->auth_credentials_pos >= conn->auth_credentials_len) return NULL;
    
    //todo; add basic auth method

    // check for digest authentication
    if(util_exists(buffer, "Digest realm=", buffer_len, util_len("Digest realm=\0")) > -1)
    {
        char *pszNonce = extract_between(buffer, "nonce=\"", "\"");
        char *pszCNonce = "2ebca197a7fcc9dbc";
        char *pszUser = conn->auth_credentials[conn->auth_credentials_pos]->username;//"admin";
        char *pszRealm = extract_between(buffer, "Digest realm=\"", "\"");
        char *pszPass = conn->auth_credentials[conn->auth_credentials_pos]->password;//"11111111"; // maybe 111111111
        char *pszAlg = "md5";
        char szNonceCount[9] = "00000002";
        
        char *pszMethod = NULL;
        
        switch(conn->curr_method)
        {
            case HTTP_METHOD_GET:
                pszMethod = ("GET");
                break;
            case HTTP_METHOD_POST:
                pszMethod = ("POST");
                break;
            case HTTP_METHOD_HEAD:
                pszMethod = ("HEAD");
                break;
        }
        
        char *pszQop = "auth";
        char *pszURI = conn->curr_path;
        HASHHEX HA1;
        HASHHEX HA2 = "";
        HASHHEX Response;
        
        memset(HA1, 0, sizeof(HASHHEX));
        memset(HA2, 0, sizeof(HASHHEX));
        memset(Response, 0, sizeof(HASHHEX));
        
        if(pszNonce == NULL || pszRealm == NULL)
        {
            if(pszNonce != NULL)
            {
                free(pszNonce);
                pszNonce = NULL;
            }
            if(pszRealm != NULL)
            {
                free(pszRealm);
                pszRealm = NULL;
            }
            return NULL;
        }
        
        //printf("Calculating DIGEST response! Got realm (%s) and nonce (%s)\r\n", pszRealm, pszNonce);
        DigestCalcHA1(pszAlg, pszUser, pszRealm, pszPass, pszNonce, pszCNonce, HA1);
        DigestCalcResponse(HA1, pszNonce, szNonceCount, pszCNonce, pszQop, pszMethod, pszURI, HA2, Response);
        //printf("DIGEST Response = %s\n", Response);

        char *ret = malloc(768);
        memset(ret, 0, 768);
        sprintf(ret, "Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\", qop=auth, nc=00000002, cnonce=\"%s\"", pszUser, pszRealm, pszNonce, pszURI, Response, pszCNonce);
        
        if(pszNonce != NULL)
        {
            free(pszNonce);
            pszNonce = NULL;
        }
        if(pszRealm != NULL)
        {
            free(pszRealm);
            pszRealm = NULL;
        }
        
        return ret;
    }
    return NULL;
}

static int parse_status(char *buffer, int buffer_len)
{
    int ret = -1;
    int j = 0, line_len = 0;
    char line[8096];
    memset(line, 0, 8096);
    for(j = 0; j < buffer_len; j++)
    {
        if(buffer[j] == '\r')
        {
            continue;
        }
        if(buffer[j] == '\n')
        {
            if(util_exists(line, "HTTP", line_len, util_len("HTTP\0")) > -1)
            {
                ret = atoi(line+strlen("HTTP/1.1 "));
            }
            memset(line, 0, 8096);
            line_len = 0;
            break;
        }
        line[line_len] = buffer[j];
        line_len++;
    }
    
    //printf("Got resp code %d!\r\n", ret);
    return ret;
}

static uint8_t parse_cookie(struct http_connection_t *conn, char *buffer, int buffer_len)
{
    int j = 0, line_len = 0;
    char line[8096];
    char lastfour[4];
    memset(lastfour, 0, 4);
    memset(line, 0, 8096);
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
            if(util_exists(line, "Set-Cookie: ", line_len, util_len("Set-Cookie: \0")) > -1)
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
                        conn->cookies = realloc(conn->cookies, (conn->cookies_num+1)*sizeof(char *));
                        conn->cookies[conn->cookies_num] = malloc(strlen(cookie_attr[0]));
                        util_cpy(conn->cookies[conn->cookies_num], cookie_attr[0], strlen(cookie_attr[0]));
                        conn->cookies_num++;
                    }
                }
            }
            memset(line, 0, 8096);
            line_len = 0;
            continue;
        }
        line[line_len] = buffer[j];
        line_len++;
    }

    return conn->cookies_num;
}



