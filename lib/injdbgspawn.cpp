#undef NDEBUG
#include <cassert>
#include <cstdio>

__attribute__((constructor)) static void init_injdbgspawn() {
    printf("hello from inj ctor.\n");
}
