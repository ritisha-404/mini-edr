#include <chrono>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <vector>


static std::string nowTimestamp() {
    auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", std::localtime(&t));
    return std::string(buf);
}


struct Alert {
    std::string severity; // low/medium/high
    std::string category; // process | filesystem
    std::string detail;
    std::string source;
};

static void emitAlert(const Alert& a) {
    std::ostringstream json;
    json << "{"
         << "\"ts\":\"" << nowTimestamp() << "\","
         << "\"severity\":\"" << a.severity << "\","
         << "\"category\":\"" << a.category << "\","
         << "\"source\":\"" << a.source << "\","
         << "\"detail\":\"" << a.detail << "\""
         << "}";
    std::string line = json.str();
    std::cout << "[ALERT] " << line << std::endl;

    std::ofstream out("alerts.log", std::ios::app);
    if (out) out << line << "\n";
}

class ProcessMonitor {
public:
    void poll() {
        std::unordered_set<int> currentPids = listPids();

        for (int pid : currentPids) {
            if (knownPids.find(pid) == knownPids.end()) {
                inspectNewProcess(pid);
            }
        }
        knownPids = std::move(currentPids);
    }

private:
    std::unordered_set<int> knownPids;
    // replace it with a proper YARA/Sigma-style rule loader (see mini-siem).
    const std::vector<std::pair<std::regex, std::string>> suspiciousPatterns = {
        {std::regex("base64\\s+-d"), "base64 decode piped to shell (possible dropper)"},
        {std::regex("/dev/tcp/"), "bash /dev/tcp reverse shell primitive"},
        {std::regex("nc\\s+-e"), "netcat with -e (reverse shell)"},
        {std::regex("curl.*\\|\\s*sh"), "curl piped directly to shell"},
        {std::regex("wget.*\\|\\s*sh"), "wget piped directly to shell"},
        {std::regex("chmod\\s+\\+x\\s+/tmp"), "making a file in /tmp executable"},
        {std::regex("LD_PRELOAD="), "LD_PRELOAD injection"},
    };

    std::unordered_set<int> listPids() {
        std::unordered_set<int> pids;
        DIR* proc = opendir("/proc");
        if (!proc) return pids;

        struct dirent* entry;
        while ((entry = readdir(proc)) != nullptr) {
            std::string name = entry->d_name;
            if (!name.empty() && std::all_of(name.begin(), name.end(), ::isdigit)) {
                pids.insert(std::stoi(name));
            }
        }
        closedir(proc);
        return pids;
    }

    std::string readCmdline(int pid) {
        std::ifstream f("/proc/" + std::to_string(pid) + "/cmdline");
        if (!f) return "";
        std::string raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        // cmdline args are NUL-separated; join with spaces for matching
        for (auto& c : raw) if (c == '\0') c = ' ';
        return raw;
    }

    std::string readExePath(int pid) {
        char buf[4096];
        ssize_t len = readlink(("/proc/" + std::to_string(pid) + "/exe").c_str(), buf, sizeof(buf) - 1);
        if (len == -1) return "";
        buf[len] = '\0';
        return std::string(buf);
    }

    void inspectNewProcess(int pid) {
        std::string cmdline = readCmdline(pid);
        std::string exePath = readExePath(pid);
        if (cmdline.empty()) return; // likely a kernel thread or already exited

        // heuristic 1: pattern match on the full command line
        for (const auto& [pattern, reason] : suspiciousPatterns) {
            if (std::regex_search(cmdline, pattern)) {
                emitAlert({"high", "process", reason + " | cmd=" + cmdline, "pid:" + std::to_string(pid)});
            }
        }

        // heuristic 2: process executing from a world-writable temp location
        if (exePath.rfind("/tmp/", 0) == 0 || exePath.rfind("/dev/shm/", 0) == 0 ||
            exePath.rfind("/var/tmp/", 0) == 0) {
            emitAlert({"medium", "process", "binary executing from writable temp dir: " + exePath,
                       "pid:" + std::to_string(pid)});
        }
    }
};

class FileMonitor {
public:
    FileMonitor(std::vector<std::string> paths) : watchPaths(std::move(paths)) {
        inotifyFd = inotify_init1(IN_NONBLOCK);
        for (const auto& p : watchPaths) {
            int wd = inotify_add_watch(inotifyFd, p.c_str(), IN_CREATE | IN_MOVED_TO | IN_ATTRIB);
            if (wd >= 0) watchDescriptors[wd] = p;
        }
    }

    void poll() {
        char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
        ssize_t len = read(inotifyFd, buf, sizeof(buf));
        if (len <= 0) return;

        for (char* ptr = buf; ptr < buf + len;) {
            auto* event = reinterpret_cast<struct inotify_event*>(ptr);
            if (event->len > 0) {
                std::string dir = watchDescriptors.count(event->wd) ? watchDescriptors[event->wd] : "?";
                std::string fullPath = dir + "/" + event->name;
                handleEvent(fullPath, event->mask);
            }
            ptr += sizeof(struct inotify_event) + event->len;
        }
    }

private:
    std::vector<std::string> watchPaths;
    int inotifyFd;
    std::unordered_map<int, std::string> watchDescriptors;

    void handleEvent(const std::string& path, uint32_t mask) {
        bool becameExecutable = false;
        if (mask & IN_ATTRIB) {
            struct stat st;
            if (stat(path.c_str(), &st) == 0 && (st.st_mode & S_IXUSR)) {
                becameExecutable = true;
            }
        }

        if (mask & (IN_CREATE | IN_MOVED_TO)) {
            emitAlert({"low", "filesystem", "new file created in watched path: " + path, path});
        }
        if (becameExecutable) {
            emitAlert({"medium", "filesystem", "file made executable in watched path: " + path, path});
        }
    }
};

int main() {
    std::cout << "mini-edr sensor starting up. Watching processes + /tmp, /dev/shm.\n";

    ProcessMonitor procMon;
    FileMonitor fileMon({"/tmp", "/dev/shm"});

    while (true) {
        procMon.poll();
        fileMon.poll();
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    return 0;
}
