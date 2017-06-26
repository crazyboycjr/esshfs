## Process this file with automake to produce Makefile.in

bin_PROGRAMS = esshfs

esshfs_SOURCES = sshfs.c cache.c cache.h encrypt.c
if FUSE_OPT_COMPAT
esshfs_SOURCES += compat/fuse_opt.c compat/fuse_opt.h
endif
if DARWIN_COMPAT
esshfs_SOURCES += compat/darwin_compat.c compat/darwin_compat.h
endif

esshfs_LDADD = $(ESSHFS_LIBS)
esshfs_CFLAGS = $(ESSHFS_CFLAGS)
esshfs_CPPFLAGS = -D_REENTRANT -DFUSE_USE_VERSION=26 -DLIBDIR=\"$(libdir)\" \
                 -DIDMAP_DEFAULT="\"$(IDMAP_DEFAULT)\""

EXTRA_DIST = esshfs.1.in
CLEANFILES = esshfs.1 esshfs.1.tmp

dist_man_MANS = esshfs.1

esshfs.1: esshfs.1.in
	$(AM_V_GEN)sed \
	    -e 's/[@]IDMAP_DEFAULT@/$(IDMAP_DEFAULT)/g' \
	    -e 's/[@]UNMOUNT_COMMAND@/$(UNMOUNT_COMMAND)/g' \
	    <$(srcdir)/esshfs.1.in >esshfs.1.tmp || exit 1; \
	mv esshfs.1.tmp esshfs.1

test: $(bin_PROGRAMS)
	mkdir -p /tmp/mnt
	./esshfs dorm:esshfs /tmp/mnt -f
