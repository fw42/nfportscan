#!/bin/sh

DESC=$(git describe)
TEMPDIR=$(mktemp -d)
DESTDIR="/tmp"

git archive --format=tar "--prefix=nfportscan-$DESC/" HEAD | (cd "$TEMPDIR" && tar x)
(cd "$TEMPDIR/nfportscan-$DESC" && \
    test -e version.h || \
    echo "#define VERSION \"$DESC\"" > version.h)
(cd "$TEMPDIR" && \
    tar czf "nfportscan-$DESC.tar.gz" "nfportscan-$DESC" && \
    cp "nfportscan-$DESC.tar.gz" "$DESTDIR" && \
    echo "$DESTDIR/nfportscan-$DESC.tar.gz")
rm -rf "$TEMPDIR"
