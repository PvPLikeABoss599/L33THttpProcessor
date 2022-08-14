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
#include "digcalc.h"

int main(int argc, char ** argv) {
    if(argc < 4)
    {
        printf("Usage %s <host> <port> <host:port>\r\n", argv[0]);
        return 1;
    }
    
    printf(" GOT HOST (%s) PORT (%d) BOTH(%s)\r\n", argv[1], atoi(argv[2]), argv[3]);
    
    struct http_connection_t *http_conn = http_proc_create_conn(argv[3]);
    
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(argv[2]));
    addr.sin_addr.s_addr = inet_addr(argv[1]);
    if(connect(fd, (struct sockaddr *)&addr, 16) < 0)
    {
        printf("Connection Failure\r\n");
        return 1;
    }
   
    struct http_request_t *http_req = http_proc_create_request(http_conn, HTTP_METHOD_GET, fd, "/");
    http_proc_req_send(http_req, NULL);
    http_proc_destroy_request(http_req);
    http_req = NULL;
    
    char recvbuf[4096];
    memset(recvbuf,0 ,4096);
    int rc = recv(fd, recvbuf, 4096, MSG_NOSIGNAL);
    
    printf(recvbuf);
    
    char *pszNonce = extract_between(recvbuf, "nonce=\"", "\"");
    char *pszCNonce = "2ebca197a7fcc9dbc";
    char *pszUser = "admin";
    char *pszRealm = extract_between(recvbuf, "Digest realm=\"", "\"");
    char *pszPass = "admin";
    char *pszAlg = "md5";
    char szNonceCount[9] = "00000002";
    char *pszMethod = "GET";
    char *pszQop = "auth";
    char *pszURI = "/";
    HASHHEX HA1;
    HASHHEX HA2 = "";
    HASHHEX Response;
    
    printf("Calculating response! Got realm (%s) and nonce (%s)\r\n", pszRealm, pszNonce);
    DigestCalcHA1(pszAlg, pszUser, pszRealm, pszPass, pszNonce, pszCNonce, HA1);
    DigestCalcResponse(HA1, pszNonce, szNonceCount, pszCNonce, pszQop, pszMethod, pszURI, HA2, Response);
    printf("Response = %s\n", Response);
    
    close(fd);
    fd = -1;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(connect(fd, (struct sockaddr *)&addr, 16) < 0)
    {
        printf("Connection Failure\r\n");
        return 1;
    }
    
    char digestAuthHdrVal[512];
    memset(digestAuthHdrVal, 0, 512);
    sprintf(digestAuthHdrVal, "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"/\", response=\"%s\", qop=auth, nc=00000002, cnonce=\"%s\"", pszUser, pszRealm, pszNonce, Response, pszCNonce);
    http_req = http_proc_create_request(http_conn, HTTP_METHOD_GET, fd, "/");
    http_proc_req_addhdr(http_req, "Authorization", digestAuthHdrVal);
    http_proc_req_send(http_req, NULL);
    http_proc_destroy_request(http_req);
    http_req = NULL;
    
    memset(recvbuf,0 ,4096);
    rc = recv(fd, recvbuf, 4096, MSG_NOSIGNAL);
    
    printf(recvbuf);
    
    close(fd);
    
    return 0;
}

