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
#include <boost/tokenizer.hpp>

#include "debugbreak.h"

/*
 * Debugger spawning
 */

static bool get_env_bool(const char *env_var, const bool *def = nullptr) {
    const auto *cstr = getenv(env_var);
    if (!cstr) {
        if (!def) {
            printf("Can't get env var \"%s\"\n", env_var);
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
            printf("Can't get env var \"%s\"\n", env_var);
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

static void sub_pid(std::vector<std::string> &spawn_args, pid_t pid) {
    const auto pid_str = std::to_string(pid);
    for (auto &arg : spawn_args) {
        boost::replace_all(arg, "%PID", pid_str);
    }
}

static std::map<std::string, std::string> get_environ_map() {
    std::map<std::string, std::string> res;
    for (char **envp = environ; *envp; ++envp) {
        const auto *eq  = strchr(*envp, '=');
        const auto *nul = strchr(*envp, '\0');
        assert(eq);
        const auto *val_cstr = eq + 1;
        const std::string name{*envp, (size_t)(eq - *envp)};
        const std::string val{val_cstr, (size_t)(nul - val_cstr)};
        res.emplace(std::make_pair(name, val));
    }
    return res;
}

static void Popen(const std::vector<std::string> &spawn_args) {
    std::vector<std::unique_ptr<char[]>> argv_uniq;
    for (const auto &arg : spawn_args) {
        argv_uniq.emplace_back(std::make_unique<char[]>(arg.size() + 1));
        const auto &cstr = argv_uniq[argv_uniq.size() - 1];
        std::copy(arg.cbegin(), arg.cend(), cstr.get());
        cstr[arg.size()] = '\0';
    }
    std::vector<char *> argv;
    for (const auto &arg : argv_uniq) {
        argv.emplace_back(arg.get());
    }
    argv.emplace_back(nullptr);

    auto env_map        = get_environ_map();
    const auto lib_path = env_map.find("LD_LIBRARY_PATH");
    if (lib_path != env_map.end()) {
        env_map.erase(lib_path);
    }
    const auto preload = env_map.find("LD_PRELOAD");
    if (preload != env_map.end()) {
        env_map.erase(preload);
    }
    std::vector<std::unique_ptr<char[]>> envp_uniq;
    for (const auto &env : env_map) {
        const auto env_str = env.first + "=" + env.second;
        envp_uniq.emplace_back(std::make_unique<char[]>(env_str.size() + 1));
        const auto &cstr = envp_uniq[envp_uniq.size() - 1];
        std::copy(env_str.cbegin(), env_str.cend(), cstr.get());
        cstr[env_str.size()] = '\0';
    }
    std::vector<char *> envp;
    for (const auto &env : envp_uniq) {
        envp.emplace_back(env.get());
    }
    envp.emplace_back(nullptr);

    pid_t pid = -1;
    assert(!posix_spawn(&pid, argv[0], nullptr, nullptr, argv.data(), envp.data()));
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
            return path;
        }
    }
    printf("\"%s\" not found in $PATH\n", name.c_str());
    exit(-1);
}

static void spawn_debugger() {
    const auto *spawn_cstr = getenv("DBG_SPAWN");
    std::vector<std::string> spawn_args;
    if (!spawn_cstr) {
        const auto gnome_term_path = search_path("gnome-terminal");
        const auto gdb_path        = search_path("gdb");
        spawn_args                 = {gnome_term_path,
                                      "--",
                                      gdb_path,
                                      "-p",
                                      "%PID",
                                      "-ex",
                                      "handle SIGINT nostop noprint pass",
                                      "-ex",
                                      "handle SIG41 nostop noprint pass",
                                      "-ex",
                                      "c"};
    } else {
        spawn_args = shlex_split(spawn_cstr);
        assert(spawn_args.size() >= 1);
        if (!path_exists(spawn_args[0])) {
            spawn_args[0] = search_path(spawn_args[0]);
        }
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
    spawn_debugger_if_requested();
}
