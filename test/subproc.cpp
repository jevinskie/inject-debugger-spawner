#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <libgen.h>
#include <string>
#include <unistd.h>

#include "subprocess.hpp"

static std::string get_exe_dir() {
    char buf[PATH_MAX];
    assert(realpath("/proc/self/exe", buf));
    dirname(buf);
    return {buf};
}

int main() {
    printf("hello from subproc parent\n");
    subprocess::Popen({get_exe_dir() + "/simple"});
    return 0;
}
