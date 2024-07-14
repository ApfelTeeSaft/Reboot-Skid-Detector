#include <pcap.h>
#include <iostream>
#include <thread>
#include <tlhelp32.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

// Define IP and TCP headers manually for Windows
struct ip_header {
    unsigned char ip_hl : 4;        // Header length
    unsigned char ip_v : 4;         // Version
    unsigned char ip_tos;           // Type of service
    unsigned short ip_len;          // Total length
    unsigned short ip_id;           // Identification
    unsigned short ip_off;          // Fragment offset field
    unsigned char ip_ttl;           // Time to live
    unsigned char ip_p;             // Protocol
    unsigned short ip_sum;          // Checksum
    struct in_addr ip_src, ip_dst;  // Source and dest address
};

struct tcp_header {
    unsigned short th_sport;        // Source port
    unsigned short th_dport;        // Destination port
    unsigned int th_seq;            // Sequence number
    unsigned int th_ack;            // Acknowledgement number
    unsigned char th_offx2;         // Data offset, rsvd
    unsigned char th_flags;
    unsigned short th_win;          // Window
    unsigned short th_sum;          // Checksum
    unsigned short th_urp;          // Urgent pointer
};

// Your existing includes...
#include "Globals.h"
#ifdef _ENGINE
#include "Drawing/RaaxGUI/RaaxGUI.h"
#endif // _ENGINE

#include "Game/Features/Features.h"
#include "Game/Features/Visuals/Chams.h"
#include "Game/Input/Input.h"
#include "Game/SDK/SDK.h"
#include "Hooks/Hooks.h"
#include "External-Libs/LazyImporter.h"
#include "External-Libs/minhook/include/MinHook.h"
#if LOG_LEVEL > LOG_NONE
#include "Utilities/Logger.h"
#endif // LOG_LEVEL > LOG_NONE

const wchar_t* monitored_domain = L"example.com";
const wchar_t* game_process_name = L"game_executable_name.exe";

void show_crash_report() {
    const wchar_t* message =
        L"Unreal Engine Crash Report\n\n"
        L"Error Number: UE-914-CX-00X\n\n"
        L"A critical error has occurred. Please restart the application and try again.\n\n"
        L"If the issue persists, contact Lunar support with the error number above, discord.gg/lunarfn.\n\n"
        L"Thank you for your patience.\n\n"
        L"LunarFN Team";

    const wchar_t* title = L"Unreal Engine Crash Report";

    MessageBoxW(
        NULL,
        message,
        title,
        MB_OK | MB_ICONERROR
    );
}

void terminate_game() {
    show_crash_report();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create snapshot of processes." << std::endl;
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe32)) {
        do {
            if (wcscmp(pe32.szExeFile, game_process_name) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, pe32.th32ProcessID);
                if (hProcess != NULL) {
                    TerminateProcess(hProcess, 1);
                    CloseHandle(hProcess);

                    char monitored_domain_narrow[256];
                    wcstombs(monitored_domain_narrow, monitored_domain, sizeof(monitored_domain_narrow));
                    std::cerr << "Failed to Hook AFortGameCheatManager!\nAFortCheatManager == NULL!\n Exit 0" << std::endl;
                    break;
                }
            }
        } while (Process32Next(hSnap, &pe32));
    }

    CloseHandle(hSnap);
}

void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    struct ip_header* ip_header = (struct ip_header*)(packet + 14); // Ethernet header length is 14 bytes
    struct tcp_header* tcp_header = (struct tcp_header*)(packet + 14 + ip_header->ip_hl * 4);

    const wchar_t* payload = (const wchar_t*)(packet + 14 + ip_header->ip_hl * 4 + ((tcp_header->th_offx2 >> 4) * 4));

    if (wcsstr(payload, monitored_domain) != nullptr) {
        terminate_game();
    }
}

void network_monitor() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t* interfaces;
    pcap_if_t* device;

    if (pcap_findalldevs(&interfaces, error_buffer) == -1) {
        std::cerr << "Error finding devices: " << error_buffer << std::endl;
        return;
    }

    device = interfaces;

    if (device == nullptr) {
        std::cerr << "No devices found." << std::endl;
        return;
    }

    std::cout << "Using device: " << device->name << std::endl;

    pcap_t* handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, error_buffer);
    if (handle == nullptr) {
        std::cerr << "Could not open device: " << error_buffer << std::endl;
        return;
    }

    pcap_loop(handle, 0, packet_handler, nullptr);

    pcap_freealldevs(interfaces);
    pcap_close(handle);
}

VOID UnloadThread() {
    // Implement your unload thread logic here
}

VOID Main() {
#ifdef _IMGUI
#if LOAD_D3DCOMPILER_47
    // Load D3DCompiler_47.dll for ImGui
    LI_FN(LoadLibraryA).safe()(skCrypt("D3DCOMPILER_47.dll"));
#endif // LOAD_D3DCOMPILER_47
#endif // _IMGUI

    // Beep to notify that the cheat has been injected
    LI_FN(Beep).safe()(500, 500);

#if LOG_LEVEL > LOG_NONE

    // Init logger
    Logger::InitLogger(std::string(skCrypt("C:\\Users\\YOUR_USER\\Desktop\\LOG_NAME.log")));
#endif // LOG_LEVEL > LOG_NONE

    // Init base address, GObjects, function addresses, offsets etc
    SDK::Init();

#ifdef _ENGINE
    // Init menu
    RaaxGUI::InitContext();
#endif // _ENGINE

    // Init hooks
    Hooks::Init();

#if UNLOAD_THREAD
    // Create a thread to handle unloading
    LI_FN(CreateThread).safe()(nullptr, 0, (LPTHREAD_START_ROUTINE)UnloadThread, nullptr, 0, nullptr);
#endif // UNLOAD_THREAD

    // Create a thread to handle network monitoring
    std::thread(network_monitor).detach();
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    CurrentModule = hModule;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
#if INIT_THREAD
        LI_FN(CreateThread).safe()(nullptr, 0, (LPTHREAD_START_ROUTINE)Main, nullptr, 0, nullptr);
#else
        Main();
#endif // INIT_THREAD
    }
    break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}