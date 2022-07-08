#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <string>

#include <fmt/format.h>

#include "frida-gum.h"
#include "subprocess.hpp"

struct Listener {
    GObject parent;
};

enum HookId {
    HOOK_VFORK,
};

struct _InvocationData {
    gpointer path;
};

static bool should_spawn_debugger() {
    bool spawn = false;
    spawn      = true;
    fmt::print("should_spawn_debugger: {}\n", spawn);
    return spawn;
}

static void clear_from_ld_preload() {
    const auto orig_cstr = getenv("LD_PRELOAD");
    assert(orig_cstr);
    std::string pruned;
    char *op = orig_cstr;
    const char *colon;
    while (colon = strchr(op, ':')) {
        const std::string lib{op, colon - op};
    }
}

static void spawn_debugger() {
    std::string proc_name{"gnome-calculator"};
    auto proc = subprocess::Popen({proc_name});
}

__attribute__((constructor)) static void init_injdbgspawn() {
    fmt::print("hello from inj ctor.\n");
    if (should_spawn_debugger()) {
        spawn_debugger();
    }
}
