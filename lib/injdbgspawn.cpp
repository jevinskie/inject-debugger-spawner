#undef NDEBUG
#include <cassert>
#include <cstdio>

#include "frida-gum.h"

__attribute__((constructor)) static void init_injdbgspawn() {
    printf("hello from inj ctor.\n");
}
