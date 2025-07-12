#include <io.h>
#include <fcntl.h>
#include <vector>
#include <cmath>
#include <string>
#include <filesystem>
#include <iostream>
#include "picosha2.h"
#include <fstream>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <unordered_set>
#define NOMINMAX
#include <windows.h>
#include <codecvt>
#include "json.hpp"

namespace fs = std::filesystem;
using json = nlohmann::json;

constexpr const wchar_t* JSON_FILE_NAME = L"checksums.json";

std::string lerpColor(int r1, int g1, int b1, int r2, int g2, int b2, float t) {
    int r = static_cast<int>(r1 + (r2 - r1) * t);
    int g = static_cast<int>(g1 + (g2 - g1) * t);
    int b = static_cast<int>(b1 + (b2 - b1) * t);
    return "\033[38;2;" + std::to_string(r) + ";" + std::to_string(g) + ";" + std::to_string(b) + "m";
}

// ANSI Color Codes
namespace Color {
    constexpr auto Reset = "\033[0m";
    constexpr auto Bold = "\033[1m";
    constexpr auto Red = "\033[31m";
    constexpr auto Green = "\033[32m";
    constexpr auto Yellow = "\033[33m";
    constexpr auto Blue = "\033[34m";
    constexpr auto Magenta = "\033[35m";
    constexpr auto Cyan = "\033[36m";
    constexpr auto BrightRed = "\033[91m";
    constexpr auto BrightGreen = "\033[92m";
    constexpr auto BrightYellow = "\033[93m";
}

void EnableAnsiColors() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;
    
    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return;
    
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

void print_banner() {
    // Define gradient colors (RGB format)
    const int startR = 0, startG = 255, startB = 255;  // Cyan
    const int endR = 255, endG = 0, endB = 255;        // Magenta

    std::vector<std::string> bannerLines = {
        "    ,------.,--.,--.        ,-----.,--.                  ,--.     ",
        "    |  .---'`--'|  | ,---. '  .--./|  ,---.  ,---.  ,---.|  |,-.  ",
        "    |  `--, ,--.|  || .-. :|  |    |  .-.  || .-. :| .--'|     /  ",
        "    |  |`   |  ||  |\\   --.'  '--'\\|  | |  |\\   --.\\ `--.|  \\  \\  ",
        "    `--'    `--'`--' `----' `-----'`--' `--' `----' `---'`--'`--' "
    };

    for (size_t i = 0; i < bannerLines.size(); ++i) {
        float t = static_cast<float>(i) / (bannerLines.size() - 1);
        std::string color = lerpColor(startR, startG, startB, endR, endG, endB, t);
        std::cout << color << bannerLines[i] << "\033[0m\n";
    }
    std::cout << "\n";
}
class ParallelSHA256 {
public:
    struct FileHash {
        std::wstring filename;
        std::string hash;
    };

    ParallelSHA256(const std::wstring& path) : m_path(path) {}

    std::vector<FileHash> compute_hashes(const std::vector<std::wstring>& files, size_t num_threads = 0) {
        if (num_threads == 0) {
            num_threads = std::thread::hardware_concurrency();
            if (num_threads == 0) num_threads = 4;
        }

        std::vector<FileHash> results;
        std::mutex results_mutex;
        std::queue<std::wstring> file_queue;
        std::mutex queue_mutex;
        std::atomic<bool> stop_flag{false};

        for (const auto& file : files) {
            file_queue.push(file);
        }

        auto worker = [&]() {
            while (true) {
                std::wstring filename;
                
                {
                    std::lock_guard<std::mutex> lock(queue_mutex);
                    if (file_queue.empty() || stop_flag) return;
                    filename = file_queue.front();
                    file_queue.pop();
                }

                FileHash result;
                result.filename = filename;
                try {
                    result.hash = compute_file_hash(filename);
                } catch (const std::exception& e) {
                    std::wcerr << Color::Red << L"Error processing " << filename << L": " << e.what() << Color::Reset << L"\n";
                    result.hash = "ERROR";
                }

                {
                    std::lock_guard<std::mutex> lock(results_mutex);
                    results.push_back(result);
                }
            }
        };

        std::vector<std::thread> threads;
        for (size_t i = 0; i < num_threads; ++i) {
            threads.emplace_back(worker);
        }

        for (auto& thread : threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }

        return results;
    }

private:
    std::string compute_file_hash(const std::wstring& filepath) {
        std::ifstream f(m_path + L"\\" + filepath, std::ios::binary);
        if (!f) {
            DWORD error = GetLastError();
            LPWSTR messageBuffer = nullptr;
            size_t size = FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPWSTR)&messageBuffer, 0, NULL);
            
            std::wstring message(messageBuffer, size);
            LocalFree(messageBuffer);
            
            throw std::runtime_error("Cannot open file (Error " + 
                                   std::to_string(error) + ")");
        }

        picosha2::hash256_one_by_one hasher;
        hasher.init();

        const size_t buffer_size = 1 << 16;
        std::vector<char> buffer(buffer_size);

        while (f.read(buffer.data(), buffer_size)) {
            hasher.process(buffer.begin(), buffer.end());
        }
        hasher.process(buffer.begin(), buffer.begin() + f.gcount());
        hasher.finish();

        std::vector<unsigned char> hash(picosha2::k_digest_size);
        hasher.get_hash_bytes(hash.begin(), hash.end());

        std::string hex_str;
        picosha2::bytes_to_hex_string(hash.begin(), hash.end(), hex_str);

        return hex_str;
    }

    std::wstring m_path;
};

std::wstring utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &utf8[0], (int)utf8.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &utf8[0], (int)utf8.size(), &wstr[0], size_needed);
    return wstr;
}

std::string wideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, NULL, NULL);
    return str;
}

void writeJsonFile(const std::wstring& filename, const std::vector<ParallelSHA256::FileHash>& hashes) {
    json js;
    for (auto& h : hashes) {
        js[wideToUtf8(h.filename)] = h.hash;
    }
    
    std::string jsonStr = js.dump(2);
    
    std::ofstream outFile(filename, std::ios::out | std::ios::binary);
    if (!outFile) {
        std::wcerr << Color::Red << L"Failed to open file for writing: " << filename << Color::Reset << L"\n";
        return;
    }
    
    outFile << jsonStr;
    outFile.close();
    
    if (!outFile) {
        std::wcerr << Color::Red << L"Error occurred while writing the file" << Color::Reset << L"\n";
        return;
    }
    
    auto fileSize = fs::file_size(filename);
    if (fileSize != jsonStr.size()) {
        std::wcerr << Color::Yellow << L"Warning: File size mismatch. Expected: " 
                   << jsonStr.size() << L" bytes, wrote: " << fileSize << L" bytes" << Color::Reset << L"\n";
    } else {
        std::wcout << Color::Green << L"Successfully wrote " << fileSize << L" bytes to " << filename << Color::Reset << L"\n";
    }
}

std::vector<std::wstring> getAllFiles(const std::wstring& directoryPath) {
    std::vector<std::wstring> filePaths;
    
    try {
        for (const auto& entry : fs::recursive_directory_iterator(directoryPath)) {
            if (fs::is_regular_file(entry)) {
                filePaths.push_back(fs::relative(entry.path(), directoryPath).wstring());
            }
        }
    } catch (const fs::filesystem_error& e) {
        std::wcerr << Color::Red << L"Filesystem error: " << e.what() << Color::Reset << L'\n';
    } catch (const std::exception& e) {
        std::wcerr << Color::Red << L"General error: " << e.what() << Color::Reset << L'\n';
    }
    
    return filePaths;
}

json hashesToJson(const std::vector<ParallelSHA256::FileHash>& hashes) {
    json js;
    for (auto& h : hashes) {
        js[wideToUtf8(h.filename)] = h.hash;
    }
    return js;
}

json loadJson(const std::wstring& pathJson) {
    json js;
    std::ifstream file(pathJson, std::ios::binary);
    if (!file) {
        std::wcerr << L"Failed to open checksum.json\n";
        return js;
    }
    
    // Read file into string
    std::string content((std::istreambuf_iterator<char>(file)), 
                     std::istreambuf_iterator<char>());
    
    try {
        js = json::parse(content);
    } catch (const std::exception& e) {
        std::cerr << "JSON parse error: " << e.what() << "\n";
    }
    return js;
}

void showDifferences(const json& oldHashes, const json& newHashes) {
    json output = json::array();
    std::unordered_map<std::string, std::string> hashToPathOld;
    std::unordered_map<std::string, std::string> hashToPathNew;
    std::unordered_map<std::string, std::string> filenameToHashOld;
    std::unordered_map<std::string, std::string> filenameToHashNew;
    std::unordered_set<std::string> processedFiles;

    // Build mappings
    for (auto& [path, hash] : oldHashes.items()) {
        if (hash.is_string()) {
            std::string hashStr = hash.get<std::string>();
            std::string filename = fs::path(path).filename().string();
            hashToPathOld[hashStr] = path;
            filenameToHashOld[path] = hashStr;
        }
    }
    
    for (auto& [path, hash] : newHashes.items()) {
        if (hash.is_string()) {
            std::string hashStr = hash.get<std::string>();
            std::string filename = fs::path(path).filename().string();
            hashToPathNew[hashStr] = path;
            filenameToHashNew[path] = hashStr;
        }
    }

    // 1. First detect moved/renamed files
    for (auto& [hash, oldPath] : hashToPathOld) {
        if (hashToPathNew.count(hash)) {
            std::string newPath = hashToPathNew[hash];
            std::string oldFilename = fs::path(oldPath).filename().string();
            std::string newFilename = fs::path(newPath).filename().string();
            
            if (oldPath != newPath) {
                json entry;
                if (oldFilename == newFilename) {
                    entry["status"] = "Moved";
                    entry["old_path"] = oldPath;
                    entry["new_path"] = newPath;
                } else {
                    entry["status"] = "Renamed";
                    entry["old_name"] = oldPath;
                    entry["new_name"] = newPath;
                }
                entry["hash"] = hash;
                output.push_back(entry);
                processedFiles.insert(oldPath);
                processedFiles.insert(newPath);
            }
        }
    }

    // 2. Detect modified files (same path, different hash)
    for (auto& [path, newHash] : filenameToHashNew) {
        if (filenameToHashOld.count(path) && filenameToHashOld[path] != newHash && 
            !processedFiles.count(path)) {
            json entry;
            entry["status"] = "Modified";
            entry["filename"] = path;
            entry["old_hash"] = filenameToHashOld[path];
            entry["new_hash"] = newHash;
            output.push_back(entry);
            processedFiles.insert(path);
        }
    }

    // 3. Detect additions (path only in new)
    for (auto& [path, hash] : filenameToHashNew) {
        if (!filenameToHashOld.count(path) && !processedFiles.count(path)) {
            json entry;
            entry["status"] = "Added";
            entry["filename"] = path;
            entry["hash"] = hash;
            output.push_back(entry);
        }
    }

    // 4. Detect removals (path only in old)
    for (auto& [path, hash] : filenameToHashOld) {
        if (!filenameToHashNew.count(path) && !processedFiles.count(path)) {
            json entry;
            entry["status"] = "Removed";
            entry["filename"] = path;
            entry["hash"] = hash;
            output.push_back(entry);
        }
    }

    // Output the results
    if (!output.empty()) {
        try {
            std::wcout << Color::Yellow << L"Differences found:\n" << Color::Reset;
            std::string diffStr = output.dump(2);
            std::wstring wideDiff = utf8ToWide(diffStr);
            std::wcout << wideDiff << std::endl;
        } catch (const std::exception& e) {
            std::wcerr << L"Error displaying differences: " << e.what() << L"\n";
        }
    } else {
        std::wcout << Color::BrightGreen << L"No differences found" << Color::Reset << L"\n";
    }
}

int wmain(int argc, wchar_t* argv[]) {
    EnableAnsiColors();
    print_banner();
    SetConsoleOutputCP(CP_UTF8);
    std::ios_base::sync_with_stdio(false);
    _setmode(_fileno(stdout), _O_U8TEXT);
    _setmode(_fileno(stderr), _O_U8TEXT);

    if (argc < 3) {
        std::wcerr << Color::Red << L"Usage: " << argv[0] << L" <directory> <mode>\n"
                  << L"Modes: w - write mode, r - read mode" << Color::Reset << L"\n";
        return 1;
    }

    bool readmode;
    if (argv[2][0] == L'w') readmode = false;
    else if (argv[2][0] == L'r') readmode = true;
    else {
        std::wcerr << Color::Red << L"Invalid mode. Use 'w' for write or 'r' for read." << Color::Reset << L"\n";
        return 1;
    }
    
    std::wstring directoryPath = argv[1];
    
    if (!readmode) {
        std::wcout << Color::Cyan << L"Scanning directory: " << directoryPath << Color::Reset << L"\n";
        auto allFiles = getAllFiles(directoryPath);
        
        if (allFiles.empty()) {
            std::wcerr << Color::Red << L"No files found in directory" << Color::Reset << L"\n";
            return 1;
        }

        std::wcout << Color::Green << L"Found " << allFiles.size() << L" files. Computing hashes..." << Color::Reset << L"\n";
        ParallelSHA256 hasher(directoryPath);
        auto results = hasher.compute_hashes(allFiles);

        std::wcout << Color::Cyan << L"Writing checksums to " << JSON_FILE_NAME << Color::Reset << L"\n";
        writeJsonFile(JSON_FILE_NAME, results);
        std::wcout << Color::BrightGreen << L"Successfully created checksums file" << Color::Reset << L"\n";
    } else {
        std::wcout << Color::Cyan << L"Loading existing checksums from " << JSON_FILE_NAME << Color::Reset << L"\n";
        auto json1 = loadJson(JSON_FILE_NAME);

        std::wcout << Color::Cyan << L"Scanning directory: " << directoryPath << Color::Reset << L"\n";
        auto allFiles = getAllFiles(directoryPath);
        
        if (allFiles.empty()) {
            std::wcerr << Color::Red << L"No files found in directory" << Color::Reset << L"\n";
            return 1;
        }

        std::wcout << Color::Green << L"Found " << allFiles.size() << L" files. Computing hashes..." << Color::Reset << L"\n";
        ParallelSHA256 hasher(directoryPath);
        auto results = hasher.compute_hashes(allFiles);
        auto json2 = hashesToJson(results);

        showDifferences(json1, json2);
    }
    
    return 0;
}