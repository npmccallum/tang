/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2016 Red Hat, Inc.
 * Author: Nathaniel McCallum <npmccallum@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "http.h"
#undef http_reply

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *METHOD_NAMES[] = {
#define XX(num, name, string) [num] = # string,
HTTP_METHOD_MAP(XX)
#undef XX
    NULL
};

static int
on_url(http_parser *parser, const char *at, size_t length)
{
    struct http_request *req = parser->data;

    if (req->status == 0) {
        if (strlen(req->path) + length >= sizeof(req->path))
            req->status = HTTP_STATUS_URI_TOO_LONG;
        else
            strncat(req->path, at, length);
    }

    return 0;
}

static int
on_body(http_parser *parser, const char *at, size_t length)
{
    struct http_request *req = parser->data;

    if (req->status == 0) {
        if (strlen(req->body) + length >= sizeof(req->body))
            req->status = HTTP_STATUS_PAYLOAD_TOO_LARGE;
        else
            strncat(req->body, at, length);
    }

    return 0;
}

static int
on_message_complete(http_parser *parser)
{
    struct http_request *req = parser->data;
    const char *addr = NULL;
    bool pathmatch = false;
    bool methmatch = false;
    int r = 0;

    if (req->status != 0)
        goto error;

    addr = getenv("REMOTE_ADDR");
    fprintf(stderr, "%s %s %s",
            addr ? addr : "<unknown>",
            METHOD_NAMES[parser->method],
            req->path);

    for (size_t i = 0; req->dispatch[i].re; i++) {
        const struct http_dispatch *d = &req->dispatch[i];
        regmatch_t match[d->nmatches];
        regex_t re = {};

        memset(match, 0, sizeof(match));

        r = regcomp(&re, d->re, REG_EXTENDED) == 0 ? 0 : -EINVAL;
        if (r == 0) {
            if (regexec(&re, req->path, d->nmatches, match, 0) == 0) {
                pathmatch = true;

                if (((1 << parser->method) & d->methods) != 0) {
                    methmatch = true;

                    r = d->func(parser->method, req->path, req->body, match);
                }
            }

            regfree(&re);
        }
    }

    if (r > 0)
        goto egress;

    if (r == 0) {
        if (!pathmatch)
            req->status = HTTP_STATUS_NOT_FOUND;
        else if (!methmatch)
            req->status = HTTP_STATUS_METHOD_NOT_ALLOWED;
        else
            req->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
    } else {
        req->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

error:
    http_reply(__FILE__, __LINE__, req->status, NULL);

egress:
    memset(req, 0, sizeof(*req));
    return 0;
}

const http_parser_settings http_settings = {
    .on_url = on_url,
    .on_body = on_body,
    .on_message_complete = on_message_complete,
};

int
http_reply(const char *file, int line,
           enum http_status code, const char *fmt, ...)
{
    const char *msg = NULL;
    va_list ap;
    int a;
    int b;

    switch (code) {
#define XX(num, name, string) case num: msg = # string; break;
    HTTP_STATUS_MAP(XX)
#undef XX
    default:
        return http_reply(file, line, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
    }

    fprintf(stderr, " => %d (%s:%d)\n", code, file, line);

    a = dprintf(STDOUT_FILENO, "HTTP/1.1 %d %s\r\n", code, msg);
    if (a < 0)
        return a;

    va_start(ap, fmt);
    b = vdprintf(STDOUT_FILENO, fmt ? fmt : "\r\n", ap);
    va_end(ap);
    return b < 0 ? b : a + b;
}
