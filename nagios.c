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

#define _GNU_SOURCE

#include <http_parser.h>

#include <jose/jose.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <limits.h>

#include <string.h>
#include <time.h>

#include <errno.h>
#include <unistd.h>

#define socket_t int __attribute__((cleanup(socket_cleanup)))

enum {
    NAGIOS_OK = 0,
    NAGIOS_WARN = 1,
    NAGIOS_CRIT = 2,
    NAGIOS_UNKN = 3
};

struct url {
    char schm[PATH_MAX];
    char host[PATH_MAX];
    char srvc[PATH_MAX];
    char path[PATH_MAX];
};

struct reply {
    int status;
    char *body;
};

static void
socket_cleanup(int *sock)
{
    if (sock && *sock >= 0)
        close(*sock);
}

static double
curtime(void)
{
    struct timespec ts = {};
    double out = 0;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0)
        out = ((double) ts.tv_sec) + ((double) ts.tv_nsec) / 1000000000L;

    return out;
}

static void
dump_perf(json_t *time)
{
    const char *key = NULL;
    bool first = true;
    json_t *val = 0;

    json_object_foreach(time, key, val) {
        int v = 0;

        if (!first)
            printf(" ");
        else
            first = false;

        if (json_is_integer(val))
            v = json_integer_value(val);
        else if (json_is_real(val))
            v = json_real_value(val) * 1000000;

        printf("%s=%d", key, v);
    }
}

static int
parse_url(const char *url, struct url *parts)
{
    static const uint16_t mask = (1 << UF_SCHEMA) | (1 << UF_HOST);
    struct http_parser_url purl = {};

    if (http_parser_parse_url(url, strlen(url), false, &purl) != 0)
        return -EINVAL;

    if ((purl.field_set & mask) != mask)
        return -EINVAL;

    if (purl.field_data[UF_SCHEMA].len >= sizeof(parts->schm) ||
        purl.field_data[UF_HOST].len >= sizeof(parts->host) ||
        purl.field_data[UF_PORT].len >= sizeof(parts->srvc) ||
        purl.field_data[UF_PATH].len >= sizeof(parts->path))
        return -E2BIG;

    strncpy(parts->schm, &url[purl.field_data[UF_SCHEMA].off],
            purl.field_data[UF_SCHEMA].len);

    strncpy(parts->host, &url[purl.field_data[UF_HOST].off],
            purl.field_data[UF_HOST].len);

    if (purl.field_set & (1 << UF_PORT)) {
        strncpy(parts->srvc, &url[purl.field_data[UF_PORT].off],
                purl.field_data[UF_PORT].len);
    } else {
        strcpy(parts->srvc, parts->schm);
    }

    if (purl.field_set & (1 << UF_PATH)) {
        strncpy(parts->path, &url[purl.field_data[UF_PATH].off],
                purl.field_data[UF_PATH].len);
    }

    return 0;
}

static int
lookup_and_connect(const char *host, const char *srvc)
{
    static const struct addrinfo hint = { .ai_socktype = SOCK_STREAM };
    struct addrinfo *ais = NULL;
    int sock = -1;

    sock = getaddrinfo(host, srvc, &hint, &ais);
    switch (sock) {
        case 0: break;
        case EAI_AGAIN:    return -EAGAIN;
        case EAI_BADFLAGS: return -EINVAL;
        case EAI_FAMILY:   return -ENOTSUP;
        case EAI_MEMORY:   return -ENOMEM;
        case EAI_SERVICE:  return -EINVAL;
        default:           return -EIO;
    }

    for (const struct addrinfo *ai = ais; ai; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0)
            continue;

        if (connect(sock, ai->ai_addr, ai->ai_addrlen) != 0)
            continue;

        freeaddrinfo(ais);
        return sock;
    }

    freeaddrinfo(ais);
    return -ENOENT;
}

static int
read_reply(int sock, char **body)
{
    http_parser parser = {};

    http_parser_init(&parser, HTTP_RESPONSE);
    parser.data = body;

    for (;;) {
        char buf[4096] = {};
        ssize_t rcvd = 0;
        size_t prsd = 0;
        size_t have = 0;

        rcvd = recv(sock, &buf[have], sizeof(buf) - have, 0);
        if (rcvd < 1)
            return 0;

        have += rcvd;

        prsd = http_parser_execute(&parser, &settings, buf, have);

        have -= prsd;
        memmove(buf, &buf[prsd], have);
    }
}

static json_t *
validate(const json_t *jws)
{
    json_auto_t *jwkset = NULL;
    json_t *keys = NULL;
    size_t sigs = 0;

    jwkset = jose_b64_decode_json_load(json_object_get(jws, "payload"));
    if (!jwkset)
        return NULL;

    keys = json_object_get(jwkset, "keys");
    if (!json_is_array(keys))
        return NULL;

    for (size_t i = 0; i < json_array_size(keys); i++) {
        json_t *key = json_array_get(keys, i);

        if (!jose_jwk_allowed(key, true, "verify"))
            continue;

        if (!jose_jws_verify(jws, key, NULL))
            return NULL;

        sigs++;
    }

    if (sigs == 0)
        return NULL;

    return json_incref(keys);
}

static bool
nagios_recover(int sock, const char *host, const char *path, const json_t *jwk,
               size_t *sig, size_t *rec, json_t *time)
{
    json_auto_t *exc = NULL;
    json_auto_t *rep = NULL;
    json_auto_t *lcl = NULL;
    json_auto_t *kid = NULL;
    char *body = NULL;
    double s = 0;
    double e = 0;
    int r = 0;

    if (jose_jwk_allowed(jwk, true, "verify")) {
        *sig += 1;
        return true;
    }

    if (!jose_jwk_allowed(jwk, true, "deriveKey"))
        return true;

    kid = jose_jwk_thumbprint_json(jwk, NULL);
    if (!kid)
        return true;

    lcl = json_pack("{s:O,s:O}",
                    "kty", json_object_get(jwk, "kty"),
                    "crv", json_object_get(jwk, "crv"));
    if (!lcl)
        return false;

    if (!jose_jwk_generate(lcl))
        return false;

    exc = jose_jwk_exchange(lcl, jwk);
    if (!exc)
        return false;

    if (!jose_jwk_clean(lcl))
        return false;

    body = json_dumps(lcl, JSON_SORT_KEYS | JSON_COMPACT);
    if (!body)
        return false;

    r = dprintf(sock,
                "POST %s/rec/%s HTTP/1.1\r\n"
                "Content-Type: application/jwk+json\r\n"
                "Accept: application/jwk+json\r\n"
                "Content-Length: %zu\r\n"
                "Host: %s\r\n"
                "%s\r\n",
                path, json_string_value(kid), strlen(body), host, body);
    free(body);
    body = NULL;
    if (r < 0)
        return false;

    s = curtime();
    r = read_reply(sock, &body);
    e = curtime();
    if (r != 200) {
        free(body);

        if (r < 0)
            printf("Error performing recovery! %s\n", strerror(-r));
        else
            printf("Error performing recovery! HTTP Status %d\n", r);

        return false;
    }

    rep = json_loads(body, 0, NULL);
    free(body);
    if (!rep) {
        printf("Received invalid JSON in response body!\n");
        return false;
    }

    if (s == 0.0 || e == 0.0 ||
        json_object_set_new(time, json_string_value(kid), json_real(e - s)) < 0) {
        printf("Error calculating performance metrics!\n");
        return false;
    }

    if (!json_equal(exc, rep)) {
        printf("Recovered key doesn't match!\n");
        return false;
    }

    *rec += 1;
    return true;
}

int
main(int argc, char *argv[])
{
    json_auto_t *time = NULL;
    json_auto_t *keys = NULL;
    json_auto_t *adv = NULL;
    struct url parts = {};
    socket_t sock = -1;
    char *body = NULL;
    size_t sig = 0;
    size_t rec = 0;
    double s = 0;
    double e = 0;
    int r = 0;

    time = json_object();
    if (!time)
        return NAGIOS_CRIT;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s URL\n", argv[0]);
        return NAGIOS_CRIT;
    }

    r = parse_url(argv[1], &parts);
    if (r < 0)
        return NAGIOS_CRIT;

    sock = lookup_and_connect(parts.host, parts.srvc);
    if (sock < 0)
        return NAGIOS_CRIT;

    r = dprintf(sock,
                "GET %s/adv HTTP/1.1\r\n"
                "Accept: application/jose+json\r\n"
                "Content-Length: 0\r\n"
                "Host: %s\r\n", parts.path, parts.host);
    if (r < 0)
        return NAGIOS_CRIT;

    s = curtime();
    r = read_reply(sock, &body);
    e = curtime();
    if (r != 200) {
        if (r < 0)
            printf("Error fetching advertisement! %s\n", strerror(-r));
        else
            printf("Error fetching advertisement! HTTP Status %d\n", r);

        return NAGIOS_CRIT;
    }

    if (s == 0.0 || e == 0.0 ||
        json_object_set_new(time, "adv", json_real(e - s)) != 0) {
        printf("Error calculating performance metrics!\n");
        return NAGIOS_CRIT;
    }

    adv = json_loads(body, 0, NULL);
    if (!adv) {
        printf("Received invalid advertisement!\n");
        return NAGIOS_CRIT;
    }

    keys = validate(adv);
    if (!keys) {
        printf("Error validating advertisement!\n");
        return NAGIOS_CRIT;
    }

    for (size_t i = 0; i < json_array_size(keys); i++) {
        json_t *jwk = json_array_get(keys, i);
        if (!nagios_recover(sock, parts.host, parts.path, jwk,
                            &sig, &rec, time))
            return NAGIOS_CRIT;
    }

    if (rec == 0) {
        printf("Advertisement contains no recovery keys!\n");
        return NAGIOS_CRIT;
    }

    json_object_set_new(time, "nkeys", json_integer(json_array_size(keys)));
    json_object_set_new(time, "nsigk", json_integer(sig));
    json_object_set_new(time, "nreck", json_integer(rec));

    printf("OK|");
    dump_perf(time);
    printf("\n");
    return NAGIOS_OK;
}
