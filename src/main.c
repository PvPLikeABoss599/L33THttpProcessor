#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "http_processor.h" 
#include "util.h"

int main(int argc, unsigned char **argv) {
    if(argc < 4)
    {
        printf("Usage %s <host> <port> <host:port>\r\n", argv[0]);
        return 1;
    }
    
    unsigned char *host = argv[1];
    unsigned char *port = argv[2];
    unsigned char *host_w_port = argv[3];
    
    printf(" GOT HOST (%s) PORT (%d) BOTH(%s)\r\n", host, atoi(port), host_w_port);
    
    ///////////////////////      MAKE HTTP SOCKET   //////////////////////////
    
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(port));
    addr.sin_addr.s_addr = inet_addr(host);
    
    if(connect(fd, (struct sockaddr *)&addr, 16) < 0)
    {
        printf("Connection Failure\r\n");
        return 1;
    }
    
    ///////////////////////    CREATE AND SEND SIMPLE HTTP REQUEST ////////////////////////////////////////
    
    base64_load();
    http_proc_load();
    
    struct http_connection_t *http_conn = http_proc_create_conn(host_w_port);
    
    //http_proc_conn_addauth(http_conn, "Admin", "admin");
    http_proc_conn_addauth(http_conn, "admin", "11111111");
    
    struct http_request_t *http_req = http_proc_create_request(http_conn, HTTP_METHOD_GET, fd, "/");
    http_proc_req_send(http_req, NULL);
    http_proc_destroy_request(http_req);
    http_req = NULL;
    
    char recvbuf[4096];
    memset(recvbuf,0 ,4096);
    int rc = recv(fd, recvbuf, 4096, MSG_NOSIGNAL);
    
    close(fd);
    fd = -1;
    
    struct http_request_resp_t *resp = http_proc_req_parse(http_conn, recvbuf, rc);
    if(resp->again == 1)
    {
        printf("STATUS: %d\r\n", resp->status);
        printf("OOPS... processor says resend our packet (?auth?)\r\n");
        
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if(connect(fd, (struct sockaddr *)&addr, 16) < 0)
        {
            printf("Connection Failure\r\n");
            return 1;
        }
        
        http_req = http_proc_create_request(http_conn, HTTP_METHOD_GET, fd, "/");
        http_proc_req_send(http_req, NULL);
        http_proc_destroy_request(http_req);
        http_req = NULL;
        
        memset(recvbuf,0 ,4096);
        rc = recv(fd, recvbuf, 4096, MSG_NOSIGNAL);
    }
    
    printf(recvbuf);
    
    close(fd);
    fd = -1;
    
    
    ////////////////////// http request finished //////////////////
    
    return 0;
}

