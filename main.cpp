#include <windows.h>
#include <vector>
#include <iostream>

// =============================================================
// [!] هام جداً: هذه القيم تتغير مع كل تحديث للعبة!
// يجب عليك استبدالها بالقيم التي ستجدها ببرنامج Cheat Engine
// =============================================================

// هذا هو "عنوان الأساس" للـ Pointer Chain الخاص بالـ FOV
// مثال: 0x056ABCDE (هذا رقم عشوائي للشرح فقط)
uintptr_t FOV_POINTER_BASE_OFFSET = 0x0; 

// هذه هي القفزات (Offsets) للوصول لقيمة الـ FOV النهائية
// مثال: { 0x10, 0x48, 0x100 }
std::vector<unsigned int> FOV_OFFSETS = { 0x0, 0x0 }; 

// القيم التي نريدها
const float ZOOM_FOV = 30.0f;  // الزووم
float ORIGINAL_FOV = 70.0f;    // القيمة الأصلية (سنحاول قراءتها من اللعبة)

// =============================================================

// دالة مساعدة لقراءة العنوان من الذاكرة بناءً على الـ Offsets
uintptr_t FindDMAAddy(uintptr_t ptr, std::vector<unsigned int> offsets) {
    uintptr_t addr = ptr;
    for (unsigned int i = 0; i < offsets.size(); ++i) {
        if (IsBadReadPtr((void*)addr, sizeof(uintptr_t))) return 0; // حماية من الكراش
        
        addr = *(uintptr_t*)addr; // اقرأ العنوان الذي يشير إليه
        if (addr == 0) return 0;  // عنوان غير صالح

        addr += offsets[i]; // أضف الـ Offset التالي
    }
    return addr;
}

// الكود الرئيسي الذي سيعمل في الخلفية
DWORD WINAPI MainThread(LPVOID lpParam) {
    // 1. الحصول على عنوان اللعبة في الذاكرة (Minecraft.Windows.exe)
    uintptr_t moduleBase = (uintptr_t)GetModuleHandle(L"Minecraft.Windows.exe");

    // حلقة تكرار لا نهائية
    while (true) {
        // تأكد من أننا نملك Offsets صحيحة قبل المحاولة
        if (FOV_POINTER_BASE_OFFSET != 0) {
            // حساب العنوان النهائي للـ FOV
            uintptr_t fovAddr = FindDMAAddy(moduleBase + FOV_POINTER_BASE_OFFSET, FOV_OFFSETS);

            if (fovAddr != 0) {
                // إذا ضغط المستخدم على زر C (الرمز 0x43)
                if (GetAsyncKeyState(0x43) & 0x8000) {
                    // اكتب قيمة الزووم
                    *(float*)fovAddr = ZOOM_FOV;
                } else {
                    // ارجع للقيمة الأصلية (يمكنك تحسين هذا لقراءة القيمة من الإعدادات)
                    // هنا سنفترض أن القيمة الطبيعية هي 70 أو نعيد القيمة التي قرأناها
                    *(float*)fovAddr = ORIGINAL_FOV;
                }
            }
        }
        
        [...](asc_slot://start-slot-3)// تقليل استهلاك المعالج
        Sleep(10); 
    }
    return 0;
}

// نقطة دخول الـ DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // تشغيل الكود في Thread منفصل لكي لا تجمد اللعبة
        CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
