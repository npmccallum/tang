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

#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <jose/jose.h>

static const char *cachedir;

static void
str_cleanup(char **str)
{
    if (str)
        free(*str);
}

static void
FILE_cleanup(FILE **file)
{
    if (file && *file)
        fclose(*file);
}

static int
adv(enum http_method method, const char *path, const char *body,
    regmatch_t matches[])
{
    __attribute__((cleanup(FILE_cleanup))) FILE *file = NULL;
    __attribute__((cleanup(str_cleanup))) char *adv = NULL;
    __attribute__((cleanup(str_cleanup))) char *thp = NULL;
    char filename[PATH_MAX] = {};
    struct stat st = {};

    if (matches[1].rm_so < matches[1].rm_eo) {
        size_t size = matches[1].rm_eo - matches[1].rm_so;
        thp = strndup(&path[matches[1].rm_so], size);
        if (!thp)
            return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
    }

    if (snprintf(filename, sizeof(filename),
                 "%s/%s.jws", cachedir, thp ? thp : "default") < 0)
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    file = fopen(filename, "r");
    if (!file)
        return http_reply(HTTP_STATUS_NOT_FOUND, NULL);

    if (fstat(fileno(file), &st) != 0)
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    adv = malloc(st.st_size);
    if (!adv)
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    if (fread(adv, st.st_size, 1, file) != 1)
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    return http_reply(HTTP_STATUS_OK,
                      "Content-Type: application/jose+json\r\n"
                      "Content-Length: %zu\r\n"
                      "\r\n%s", strlen(adv), adv);
}

static int
rec(enum http_method method, const char *path, const char *body,
    regmatch_t matches[])
{
    __attribute__((cleanup(str_cleanup))) char *enc = NULL;
    __attribute__((cleanup(str_cleanup))) char *thp = NULL;
    size_t size = matches[1].rm_eo - matches[1].rm_so;
    char filename[PATH_MAX] = {};
    json_auto_t *jwk = NULL;
    json_auto_t *req = NULL;
    json_auto_t *rep = NULL;
    const char *kty = NULL;

    req = json_loads(body, 0, NULL);
    if (!req)
        return http_reply(HTTP_STATUS_BAD_REQUEST, NULL);

    if (json_unpack(req, "{s:s}", "kty", &kty) != 0)
        return http_reply(HTTP_STATUS_BAD_REQUEST, NULL);

    if (strcmp(kty, "EC") != 0)
        return http_reply(HTTP_STATUS_BAD_REQUEST, NULL);

    thp = strndup(&path[matches[1].rm_so], size);
    if (!thp)
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    if (snprintf(filename, sizeof(filename),
                 "%s/%s.jws", cachedir, thp ? thp : "default") < 0)
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    jwk = json_load_file(filename, 0, NULL);
    if (!jwk)
        return http_reply(HTTP_STATUS_NOT_FOUND, NULL);

    if (!jose_jwk_allowed(jwk, true, "deriveKey"))
        return http_reply(HTTP_STATUS_FORBIDDEN, NULL);

    rep = jose_jwk_exchange(jwk, req);
    if (!rep)
        return http_reply(HTTP_STATUS_BAD_REQUEST, NULL);

    enc = json_dumps(rep, JSON_SORT_KEYS | JSON_COMPACT);
    if (!enc)
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    return http_reply(HTTP_STATUS_OK,
                      "Content-Type: application/jwk+json\r\n"
                      "Content-Length: %zu\r\n"
                      "\r\n%s", strlen(enc), enc);
}

static struct http_dispatch dispatch[] = {
    { adv, 1 << HTTP_GET,  2, "^/+adv/+([0-9A-Za-z_-]+)$" },
    { adv, 1 << HTTP_GET,  2, "^/+adv/*$" },
    { rec, 1 << HTTP_POST, 2, "^/+rec/+([0-9A-Za-z_-]+)$" },
    {}
};

int
main(int argc, char *argv[])
{
    struct http_request request = { .dispatch = dispatch };
    struct http_parser parser = { .data = &request };
    char req[4096] = {};
    size_t rcvd = 0;
    int r = 0;

    http_parser_init(&parser, HTTP_REQUEST);

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <cachedir>\n", argv[0]);
        return EXIT_FAILURE;
    }

    cachedir = argv[1];

    for (;;) {
        r = read(STDIN_FILENO, &req[rcvd], sizeof(req) - rcvd - 1);
        if (r == 0)
            return rcvd > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
        if (r < 0)
            return EXIT_FAILURE;

        rcvd += r;

        r = http_parser_execute(&parser, &http_settings, req, rcvd);
        if (parser.http_errno != 0) {
            fprintf(stderr, "HTTP Parsing Error: %s\n",
                    http_errno_description(parser.http_errno));
            return EXIT_FAILURE;
        }

        memmove(req, &req[r], rcvd - r);
        rcvd -= r;
    }
}
