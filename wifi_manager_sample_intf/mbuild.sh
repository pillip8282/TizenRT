./dbuild.sh distclean && find ../ -name *.o -delete && ./tools/configure.sh rtl8721csm/hello && ./dbuild.sh && ./dbuild.sh download all
