AM_CFLAGS = @TANG_CFLAGS@ @jose_zlib_CFLAGS@ @jose_openssl_CFLAGS@

jwkdir = $(localstatedir)/db/$(PACKAGE_NAME)
cachedir = $(localstatedir)/cache/$(PACKAGE_NAME)

systemdsystemunit_DATA = tangd.socket tangd.service
EXTRA_DIST = tangd.socket.in tangd.service.in
CLEANFILES = tangd.socket tangd.service

libexec_PROGRAMS = tangd
tangd_SOURCES = http.c http.h tangd.c
tangd_LDADD = @jose_zlib_LIBS@ @jose_openssl_LIBS@ @http_parser_LIBS@

install-data-hook:
	mkdir -p $(DESTDIR)$(jwkdir)
	mkdir -p $(DESTDIR)$(cachedir)

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@jwkdir\@,$(jwkdir),g' \
		-e 's,@cachedir\@,$(cachedir),g' \
		$(srcdir)/$@.in > $@
