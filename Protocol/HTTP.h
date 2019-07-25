#pragma once
#include <stdint.h>
#include <string.h>

const char *HTTP_METHOD_HTTP = "HTTP";
const char *HTTP_METHOD_GET = "GET";
const char *HTTP_METHOD_POST = "POST";
const char *HTTP_METHOD_PUT = "PUT";
const char *HTTP_METHOD_DELETE = "DELETE";
const char *HTTP_METHOD_CONNECT = "CONNECT";
const char *HTTP_METHOD_OPTIONS = "OPTIONS";
const char *HTTP_METHOD_TRACE = "TRACE";
const char *HTTP_METHOD_PATCH = "PATCH";

struct httpthdr
{
    u_char * http_method;
    u_int len;
};

httpthdr HTTP_METHOD[9] =
{
    {HTTP_METHOD_HTTP, 4},
    {HTTP_METHOD_GET, 3},
    {HTTP_METHOD_POST, 4},
    {HTTP_METHOD_PUT, 3},
    {HTTP_METHOD_DELETE, 6},
    {HTTP_METHOD_CONNECT, 7},
    {HTTP_METHOD_OPTIONS, 7},
    {HTTP_METHOD_TRACE, 5},
    {HTTP_METHOD_PATCH, 5}
};

bool http_check
{
    for(int i = 0; i < 9; i++) {
        if(!strcmp()) return true;
    }
    return false;
}