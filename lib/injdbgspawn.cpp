#undef NDEBUG
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <unistd.h>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/process/search_path.hpp>
#include <boost/tokenizer.hpp>
#include <fmt/format.h>

#include "frida-gum.h"
#include "magic_enum.hpp"
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

static std::vector<std::string> shlex_split(const std::string &s) {
    // https://stackoverflow.com/a/541862 Ferruccio
    const std::string sep1{""};     // don't let quoted arguments escape themselves
    const std::string sep2{" "};    // split on spaces
    const std::string sep3{"\"\'"}; // let it have quoted arguments

    boost::escaped_list_separator<char> els{sep1, sep2, sep3};
    boost::tokenizer<boost::escaped_list_separator<char>> tok{s, els};

    std::vector<std::string> res;
    std::copy(tok.begin(), tok.end(), std::back_inserter(res));
    return res;
}

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

static void sub_pid(std::vector<std::string> &spawn_args, pid_t pid) {
    const auto pid_str = std::to_string(pid);
    for (auto &arg : spawn_args) {
        boost::replace_all(arg, "$PID", pid_str);
    }
}

static void spawn_debugger() {
    const auto *spawn_cstr = getenv("DBG_SPAWN");
    std::vector<std::string> spawn_args;
    if (!spawn_cstr) {
        const auto gdb_path = boost::process::search_path("gdb").string();
        spawn_args          = {"gnome-terminal", "--", gdb_path, "-p", "$PID"};
    } else {
        spawn_args = shlex_split(spawn_cstr);
    }
    sub_pid(spawn_args, getpid());
    auto proc = subprocess::Popen(spawn_args);
}

__attribute__((constructor)) static void init_injdbgspawn() {
    fmt::print("hello from inj ctor.\n");
    clear_from_ld_preload();
    if (should_spawn_debugger()) {
        spawn_debugger();
    }
    kill(getpid(), SIGSTOP);
}
