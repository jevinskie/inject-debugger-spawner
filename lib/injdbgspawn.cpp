#undef NDEBUG
#include <cassert>
#include <cstdio>

#include "frida-gum.h"

struct Listener {
    GObject parent;
};

enum HookId {
    HOOK_VFORK,
};

struct _InvocationData {
    gpointer path;
};

__attribute__((constructor)) static void init_injdbgspawn() {
    printf("hello from inj ctor.\n");
}
