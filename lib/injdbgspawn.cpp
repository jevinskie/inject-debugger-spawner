#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <vector>

#include <fmt/format.h>

#include "frida-gum.h"
#include "subprocess.hpp"

struct Listener {
    GObject parent;
};

enum HookId {
    HOOK_FORK,
    HOOK_VFORK,
    HOOK_EXECL,
    HOOK_EXECLP,
    HOOK_EXECLE,
    HOOK_EXECV,
    HOOK_EXECVP,
    HOOK_EXECPE,
    HOOK_EXECVEAT,
    HOOK_FEXECVE,
    HOOK_POSIX_SPAWN,
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
    const auto *orig_cstr_nul_ptr = orig_cstr + strlen(orig_cstr);
    const char *op                = orig_cstr;
    const char *colon             = nullptr;
    const std::string our_lib{"libinjdbgspawn.so"};
    std::vector<std::string> libs;
    while ((colon = strchr(op, ':'))) {
        const std::string lib{op, (size_t)(colon - op)};
        if (!lib.ends_with(our_lib)) {
            libs.emplace_back(lib);
        }
        op = colon + 1;
    }
    if (op != orig_cstr_nul_ptr) {
        const std::string lib{op, (size_t)(orig_cstr_nul_ptr - op)};
        if (!lib.ends_with(our_lib)) {
            libs.emplace_back(lib);
        }
    }
    std::string pruned;
    if (!libs.empty()) {
        for (size_t i = 0; i < libs.size() - 1; ++i) {
            pruned += libs[i] + ":";
        }
        pruned += libs[libs.size() - 1];
    }
    assert(!setenv("LD_PRELOAD", pruned.c_str(), true));
}

static void spawn_debugger() {
    std::string proc_name{"gnome-calculator"};
    auto proc = subprocess::Popen({proc_name});
}

__attribute__((constructor)) static void init_injdbgspawn() {
    fmt::print("hello from inj ctor.\n");
    clear_from_ld_preload();
    if (should_spawn_debugger()) {
        spawn_debugger();
    }
}
