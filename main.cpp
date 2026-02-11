#include <windows.h>
#include <iostream>
#include <vector>

// ==========================================
// الأوفستات (ستحتاج لتحديثها لاحقاً)
// ==========================================
uintptr_t FOV_OFFSET = 0x0; 

// ==========================================

void MainThread(HMODULE hModule) {
    // 1. إظهار رسالة ترحيب أول ما الكلاينت يتحقن
    // المعاملات: (المقبض، نص الرسالة، عنوان النافذة، نوع الزرار والأيقونة)
    MessageBoxW(NULL, L"Welcome to ZoomClient!", L"ZoomClient Info", MB_OK | MB_ICONINFORMATION);

    // 2. فتح شاشة الكونسول السوداء
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);

    std::cout << "====================================" << std::endl;
    std::cout << "        ZoomClient Loaded!          " << std::endl;
    std::cout << "====================================" << std::endl;
    std::cout << "[+] Press 'C' to Zoom." << std::endl;
    std::cout << "[+] Press 'END' to Eject." << std::endl;

    uintptr_t moduleBase = (uintptr_t)GetModuleHandleW(L"Minecraft.Windows.exe");

    float defaultFov = 70.0f;
    float zoomFov = 30.0f;
    bool isZooming = false;

    while (!GetAsyncKeyState(VK_END)) {
        if (GetAsyncKeyState('C')) {
            if (!isZooming) {
                std::cout << "[!] Zoom Activated!" << std::endl;
                isZooming = true;
            }
        } else {
            if (isZooming) {
                std::cout << "[!] Zoom Deactivated!" << std::endl;
                isZooming = false;
            }
        }
        Sleep(10);
    }

    // تنظيف الخروج
    std::cout << "Unloading..." << std::endl;
    fclose(f);
    FreeConsole();
    FreeLibraryAndExitThread(hModule, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // تشغيل الكود في Thread منفصل عشان اللعبة متقفش
        CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, nullptr));
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
