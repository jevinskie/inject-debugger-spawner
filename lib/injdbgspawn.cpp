#undef NDEBUG
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <unistd.h>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/process/search_path.hpp>
#include <boost/tokenizer.hpp>
#include <fmt/format.h>

#include "debugbreak.h"
#include "frida-gum.h"
#include "magic_enum.hpp"
#include "subprocess.hpp"

static void spawn_debugger_if_requested();

/*
 * frida-gum hooking
 */

struct _DBGListener {
    GObject parent;
};

enum class _DBGHookId {
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

struct _DBGInvocationData {
    gpointer path;
};

using DBGListener       = _DBGListener;
using DBGHookId         = _DBGHookId;
using DBGInvocationData = _DBGInvocationData;

static void dbg_listener_on_leave(GumInvocationListener *listener, GumInvocationContext *ic);
static void dbg_listener_iface_init(gpointer g_iface, gpointer iface_data);

#define DBG_TYPE_LISTENER (dbg_listener_get_type())
G_DECLARE_FINAL_TYPE(DBGListener, dbg_listener, DBG, LISTENER, GObject)
G_DEFINE_TYPE_EXTENDED(DBGListener, dbg_listener, G_TYPE_OBJECT, 0,
                       G_IMPLEMENT_INTERFACE(GUM_TYPE_INVOCATION_LISTENER, dbg_listener_iface_init))

static GumInterceptor *interceptor;
static GumInvocationListener *listener;
static std::map<std::string, gpointer> name2sym;

static std::string to_string(DBGHookId e) {
    return "";
}

static void dbg_listener_on_enter(GumInvocationListener *listener, GumInvocationContext *ic) {}

static void dbg_listener_on_leave(GumInvocationListener *listener, GumInvocationContext *ic) {}

static void dbg_listener_class_init(DBGListenerClass *klass) {}

static void dbg_listener_iface_init(gpointer g_iface, gpointer iface_data) {
    auto *iface     = (GumInvocationListenerInterface *)g_iface;
    iface->on_enter = dbg_listener_on_enter;
    iface->on_leave = dbg_listener_on_leave;
}

static void dbg_listener_init(DBGListener *self) {}

static void hook_install() {
    fmt::print("hook_install\n");
    gum_init_embedded();
    interceptor = gum_interceptor_obtain();
    assert(interceptor);
    listener = (GumInvocationListener *)g_object_new(DBG_TYPE_LISTENER, nullptr);
    assert(listener);
}

static void hook_uninstall() {
    fmt::print("hook_uninstall\n");
    if (interceptor) {
        gum_interceptor_detach(interceptor, listener);
    }
    gum_deinit_embedded();
}

/*
 * Debugger spawning
 */

static bool get_env_bool(const char *envvar, bool def) {
    const auto *cstr = getenv(envvar);
    if (!cstr) {
        return def;
    }
    std::string v{cstr};
    boost::to_lower(v);
    bool res = false;
    if (v == "1" || v == "true" || v == "on") {
        res = true;
    }
    return res;
}

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

static bool should_spawn_immediately() {
    return get_env_bool("DBG_IMMEDIATE", false);
}

static bool should_spawn_debugger() {
    bool spawn = false;
    spawn |= should_spawn_immediately();
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
        boost::replace_all(arg, "%PID", pid_str);
    }
}

static void spawn_debugger() {
    const auto *spawn_cstr = getenv("DBG_SPAWN");
    std::vector<std::string> spawn_args;
    if (!spawn_cstr) {
        const auto gnome_term_path = boost::process::search_path("gnome-terminal").string();
        const auto gdb_path        = boost::process::search_path("gdb").string();
        spawn_args                 = {gnome_term_path, "--", gdb_path, "-p", "%PID", "-ex", "c"};
    } else {
        spawn_args = shlex_split(spawn_cstr);
    }
    sub_pid(spawn_args, getpid());
    auto proc = subprocess::Popen(spawn_args);
}

static bool should_break() {
    return get_env_bool("DBG_BREAK", false);
}

static pid_t get_tracer_pid() {
    static int status_fd = -1;
    if (status_fd < 0) {
        status_fd = open("/proc/self/status", O_RDONLY);
        assert(status_fd >= 0);
    }
    assert(lseek(status_fd, 0, SEEK_SET) == 0);
    char buf[1024];
    assert(read(status_fd, buf, sizeof(buf)) > 0);
    buf[sizeof(buf) - 1] = '\0';
    std::string status{buf};
    const std::string tpid_prefix{"\nTracerPid:\t"};
    const auto tpid_off = status.find(tpid_prefix);
    assert(tpid_off != std::string::npos);
    status.erase(0, tpid_off + tpid_prefix.size());
    pid_t tracer_pid = std::stoi(status);
    return tracer_pid;
}

static void spawn_debugger_and_wait() {
    clear_from_ld_preload();
    spawn_debugger();
    while (get_tracer_pid() == 0) {
        usleep(1000 * 10);
    }
    if (should_break()) {
        debug_break();
    }
}

static void spawn_debugger_if_requested() {
    if (should_spawn_debugger()) {
        spawn_debugger_and_wait();
    }
}

__attribute__((constructor)) static void injdbgspawn_ctor() {
    fmt::print("hello from inj ctor.\n");
    if (should_spawn_immediately()) {
        spawn_debugger_if_requested();
    } else {
        hook_install();
    }
}

__attribute__((destructor)) static void injdbgspawn_dtor() {
    hook_uninstall();
}
