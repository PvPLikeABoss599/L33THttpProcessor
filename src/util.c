#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>

#include "util.h"

char *extract_between(const char *str, const char *p1, const char *p2)
{
    const char *i1 = strstr(str, p1);
    if(i1 != NULL)
    {
        const size_t pl1 = strlen(p1);
        const char *i2 = strstr(i1 + pl1, p2);
        if(p2 != NULL)
        {
            /* Found both markers, extract text. */
            const size_t mlen = i2 - (i1 + pl1);
            char *ret = malloc(mlen + 1);
            if(ret != NULL)
            {
                memcpy(ret, i1 + pl1, mlen);
                ret[mlen] = '\0';
                return ret;
            }
        }
    }
}

void hexDump (char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}

int util_memsearch(char *buf, int buf_len, char *mem, int mem_len)
{
    int i, matched = 0;

    if (mem_len > buf_len)
        return -1;

    for (i = 0; i < buf_len; i++)
    {
        if (buf[i] == mem[matched])
        {
            if (++matched == mem_len)
                return i + 1;
        }
        else
            matched = 0;
    }

    return -1;
}

uint8_t util_sockprintf(int fd, const char *fmt, ...)
{
    char buffer[BUFFER_SIZE + 2];
    va_list args;
    int len;

    va_start(args, fmt);
    len = vsnprintf(buffer, BUFFER_SIZE, fmt, args);
    va_end(args);

    if (len > 0)
    {
        if (len > BUFFER_SIZE)
            len = BUFFER_SIZE;

#ifdef DEBUG
        hexDump("TELOUT", buffer, len);
#endif
        if (send(fd, buffer, len, MSG_NOSIGNAL) != len)
            return 0;
    }

    return 1;
}

char *util_trim(char *str)
{
    char *end;

    while(isspace(*str))
        str++;

    if(*str == 0)
        return str;

    end = str + strlen(str) - 1;
    while(end > str && isspace(*end))
        end--;

    *(end+1) = 0;

    return str;
}


int util_zero(void *ptr, uint32_t size)
{
    uint8_t *ptr_w = (uint8_t *)ptr;
    uint32_t j;
    for(j = 0; j < size; j++)
    {
        ptr_w[j] = 0;
    }
}

int util_len(void *ptr)
{
    int j = 0;
    uint8_t *ptr_w = (uint8_t *)ptr;
    while(ptr_w[j] != 0)
    {
        j++;
    }
    return j;
}

void util_cpy(void *ptr, void *ptr2, uint32_t size)
{
    uint8_t *ptr_w = (uint8_t *)ptr;
    uint8_t *ptr2_w = (uint8_t *)ptr2;
    uint32_t j;
    for(j = 0; j < size; j++)
    {
        ptr_w[j] = ptr2_w[j];
    }
    return;
}

int util_match(void *ptr, void *ptr2, uint32_t size)
{
    uint8_t *ptr_w = (uint8_t *)ptr;
    uint8_t *ptr2_w = (uint8_t *)ptr2;
    uint32_t j;
    for(j = 0; j < size; j++)
    {
        if(ptr_w[j] == ptr2_w[j])
        {
            continue;
        }
        else
        {
            return 0;
        }
    }
    return 1;
}

int util_exists(void *ptr, void *ptr2, uint32_t ptr_size, uint32_t ptr2_size)
{
    uint8_t *ptr_w = (uint8_t *)ptr;
    uint8_t *ptr2_w = (uint8_t *)ptr2;
    uint32_t j;
    int ptr2_pos = 0;

    if(ptr2_size > ptr_size) return -1;
    for(j = 0; j < ptr_size; j++)
    {
        if(ptr_w[j] == ptr2_w[ptr2_pos])
        {
            #ifdef DEBUG_UTILS
            printf("(util_exists) ptr_w[%d] == ptr2_w[%d]: success\r\n", j, ptr2_pos);
            #endif
            ptr2_pos++;
            if(ptr2_pos == ptr2_size)
            {
                #ifdef DEBUG_UTILS
                printf("(util_exists) success found exist match! starts at %d\r\n", j-ptr2_pos+1);
                #endif
                return j-ptr2_pos+1;
            }
            continue;
        }
        else if(ptr2_pos > 0)
        {
            #ifdef DEBUG_UTILS
            printf("(util_exists) ptr_w[%d] != ptr2_w[%d]: failure reset continue\r\n", j, ptr2_pos);
            #endif
            ptr2_pos = 0;
        }
        else
        {
            #ifdef DEBUG_UTILS
            printf("(util_exists) ptr_w[%d] != ptr2_w[%d]: failure continue\r\n", j, ptr2_pos);
            #endif
            continue;
        }
    }
    if(ptr2_pos == ptr2_size)
    {
        return j-ptr2_pos+1;
    }
    return -1;
}

void util_strreverse(unsigned char *str)
{
    int start = 0;
    int end = util_len(str)-1;
    while (start < end)
    {
        char tmpc = str[end];
        str[end] = str[start];
        str[start] = tmpc;
        start++;
        end--;
    }
}

uint8_t **util_tokenize(const uint8_t *buf, const int buf_size, int *count, const uint8_t delim)
{
    uint8_t **ret = NULL;
    int ret_count = 0, token_pos = 0, pos;
    uint8_t *token = malloc(512);
    util_zero(token, 512);
    for (pos = 0; pos < buf_size; pos++)
    {
        if(buf[pos] == delim)
        {
            token[token_pos] = 0;
            
            ret = realloc(ret, (ret_count + 1) *sizeof(uint8_t *));
            ret[ret_count] = malloc(token_pos + 1);
            util_zero(ret[ret_count], token_pos+1);
            util_cpy(ret[ret_count], token, token_pos+1);
            ret_count++;

            util_zero(token, 512);
            token_pos = 0;
        }
        else
        {
            token[token_pos] = buf[pos];
            token_pos++;
            if(token_pos == 512)
            {
                util_zero(token, 512);
                token_pos = 0;
            }
        }
    }

    if(token_pos > 0)
    {
        ret = realloc(ret, (ret_count + 1) *sizeof(uint8_t *));
        ret[ret_count] = malloc(token_pos + 1);
        util_zero(ret[ret_count], token_pos+1);
        util_cpy(ret[ret_count], token, token_pos+1);
        ret_count++;

        util_zero(token, 512);
        token_pos = 0;
    }

    *count = ret_count;

    util_zero(token, 512);
    free(token);
    token = NULL;

    if(ret_count > 0) return ret;
    return NULL;
}

