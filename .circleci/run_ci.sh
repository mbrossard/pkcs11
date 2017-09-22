#! /bin/bash

$CC --version
echo "START OF BUILD"
autoreconf -i
./configure
make V=1
echo "END OF BUILD"
echo ""
echo "START OF TESTING"
echo ""
make test || exit $?
echo ""
echo "END OF TESTING"
make test-clean

exit 0

