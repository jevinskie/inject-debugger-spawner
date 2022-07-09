#undef NDEBUG
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <limits.h>
#include <map>
#include <memory>
#include <regex>
#include <spawn.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

#include <boost/algorithm/string.hpp>
// #include <boost/process/search_path.hpp>
#include <boost/tokenizer.hpp>
#include <fmt/format.h>

#include "debugbreak.h"
// #include "subprocess.hpp"

#ifdef USE_GUM
/*
 * frida-gum hooking
 */
#include "frida-gum.h"
#include "magic_enum.hpp"

static void spawn_debugger_if_requested();

struct _DBGListener {
    GObject parent;
};

enum class _DBGHookId {
    HOOK_FORK,
    HOOK_VFORK,
    HOOK_CLONE,
    HOOK_EXECL,
    HOOK_EXECLP,
    HOOK_EXECLE,
    HOOK_EXECV,
    // HOOK_EXECVP, // calls into execvpe on glibc
    HOOK_EXECVPE,
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
static std::map<DBGHookId, gpointer> hook2sym __attribute__((init_priority(2000)));

static std::string to_string(DBGHookId hook_id) {
    std::string name{magic_enum::enum_name(hook_id)};
    boost::to_lower(name);
    name = name.substr(5); // strlen("HOOK_") == 5
    return name;
}

static void dbg_listener_on_enter(GumInvocationListener *listener, GumInvocationContext *ic) {
    const auto *self      = DBG_LISTENER(listener);
    const auto hook_id    = (DBGHookId)GUM_IC_GET_FUNC_DATA(ic, uintptr_t);
    DBGInvocationData *id = nullptr;
    const auto hook_name  = to_string(hook_id);
    fmt::print("on_enter: {:s}\n", hook_name);
}

static void dbg_listener_on_leave(GumInvocationListener *listener, GumInvocationContext *ic) {
    const auto *self      = DBG_LISTENER(listener);
    const auto hook_id    = (DBGHookId)GUM_IC_GET_FUNC_DATA(ic, uintptr_t);
    DBGInvocationData *id = nullptr;
    const auto hook_name  = to_string(hook_id);
    fmt::print("on_leave: {:s}\n", hook_name);
}

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

    for (const auto hook_id : magic_enum::enum_values<DBGHookId>()) {
        const auto hook_sym_name = to_string(hook_id);
        const auto hook_sym_ptr =
            GSIZE_TO_POINTER(gum_module_find_export_by_name("libc.so.6", hook_sym_name.c_str()));
        if (!hook_sym_ptr) {
            fmt::print("Couldn't lookup \"{:s}\" in libc.so.6\n", hook_sym_name);
            exit(-1);
        }
        hook2sym.insert(std::make_pair(hook_id, hook_sym_ptr));
    }

    gum_interceptor_begin_transaction(interceptor);

    for (const auto hook_id : magic_enum::enum_values<DBGHookId>()) {
        const auto hook_sym_ptr = hook2sym[hook_id];
        const auto aret =
            gum_interceptor_attach(interceptor, hook_sym_ptr, listener, GSIZE_TO_POINTER(hook_id));
        assert(!aret);
    }
    gum_interceptor_end_transaction(interceptor);
}

static void hook_uninstall() {
    fmt::print("hook_uninstall\n");
    if (interceptor) {
        gum_interceptor_detach(interceptor, listener);
    }
    gum_deinit_embedded();
}

#endif

/*
 * Debugger spawning
 */

static bool get_env_bool(const char *env_var, const bool *def = nullptr) {
    const auto *cstr = getenv(env_var);
    if (!cstr) {
        if (!def) {
            fmt::print("Can't get env var \"{:s}\"\n", env_var);
            exit(-1);
        }
        return *def;
    }
    std::string v{cstr};
    boost::to_lower(v);
    bool res = false;
    if (v == "1" || v == "true" || v == "on") {
        res = true;
    }
    return res;
}

static std::string get_env_string(const char *env_var, const std::string *def = nullptr) {
    const auto *cstr = getenv(env_var);
    if (!cstr) {
        if (!def) {
            fmt::print("Can't get env var \"{:s}\"\n", env_var);
            exit(-1);
        }
        return *def;
    }
    return {cstr};
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
    const auto def = false;
    return get_env_bool("DBG_IMM", &def);
}

static std::string get_exe_path() {
    char buf[PATH_MAX];
    assert(realpath("/proc/self/exe", buf));
    return {buf};
}

static bool should_spawn_debugger() {
    if (should_spawn_immediately()) {
        return true;
    }
    const auto re = std::regex{get_env_string("DBG_PAT")};
    return std::regex_search(get_exe_path(), re);
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

static void Popen(const std::vector<std::string> &spawn_args) {
    pid_t pid = -1;
    std::vector<std::unique_ptr<char[]>> argv_uniq;
    for (const auto &arg : spawn_args) {
        argv_uniq.emplace_back(std::make_unique<char[]>(arg.size() + 1));
        std::copy(arg.cbegin(), arg.cend(), argv_uniq[argv_uniq.size() - 1].get());
    }
    std::vector<char *> argv;
    for (const auto &arg : argv_uniq) {
        argv.emplace_back(arg.get());
    }
    argv.emplace_back(nullptr);

    int res = posix_spawn(&pid, argv[0], nullptr, nullptr, argv.data(), environ);
}

static bool path_exists(const std::string &path) {
    return !access(path.c_str(), X_OK);
}

static std::string search_path(const std::string &name) {
    const auto path_var = get_env_string("PATH");
    const char *op      = path_var.c_str();
    const auto *nul_ptr = op + path_var.size();
    const char *colon   = nullptr;
    while ((colon = strchr(op, ':'))) {
        const std::string dir{op, (size_t)(colon - op)};
        const auto path = dir + "/" + name;
        if (path_exists(path)) {
            return path;
        }
        op = colon + 1;
    }
    if (op != nul_ptr) {
        const std::string dir{op, (size_t)(nul_ptr - op)};
        const auto path = dir + "/" + name;
        if (path_exists(path)) {
            fmt::print("loL: {:s}\n", path);
            return path;
        }
    }
    fmt::print("\"{:s}\" not found in $PATH\n", name);
    exit(-1);
}

static void spawn_debugger() {
    const auto *spawn_cstr = getenv("DBG_SPAWN");
    std::vector<std::string> spawn_args;
    if (!spawn_cstr) {
        const auto gnome_term_path = search_path("gnome-terminal");
        const auto gdb_path        = search_path("gdb");
        spawn_args                 = {gnome_term_path, "--", gdb_path, "-p", "%PID", "-ex", "c"};
    } else {
        spawn_args = shlex_split(spawn_cstr);
    }
    sub_pid(spawn_args, getpid());
    Popen(spawn_args);
}

static bool should_break() {
    const auto def = false;
    return get_env_bool("DBG_BREAK", &def);
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

__attribute__((constructor(3000))) static void injdbgspawn_ctor() {
#ifdef USE_GUM
    if (should_spawn_immediately()) {
        spawn_debugger_if_requested();
    } else {
        hook_install();
    }
#else
    spawn_debugger_if_requested();
#endif
}

#ifdef USE_GUM
__attribute__((destructor(3000))) static void injdbgspawn_dtor() {
    hook_uninstall();
}
#endif
