#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <intrin.h>

#ifdef __MINGW64__
#include <windows.h>
#else
#include <Windows.h>
#endif

// TODO: MingW?
#include <cstdlib>
#include <winuser.h>

constexpr static const char* DIALOG_TITLE = "Title";
constexpr static const char* DIALOG_TEXT = "Hello, World!";

// https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellabouta
using ShellAboutProc = int(WINAPI *)(HWND hwnd, LPCSTR szApp, LPCSTR szOtherStuff, HICON hIcon);

int main()
{
    MessageBoxA(nullptr, DIALOG_TEXT, DIALOG_TITLE, MB_OK);
    
    HMODULE hModule = LoadLibrary(TEXT("Shell32.dll"));
    if (!hModule)
    {
        return EXIT_FAILURE;
    }

    auto shellAbout = reinterpret_cast<ShellAboutProc>(GetProcAddress(hModule, "ShellAboutA"));
    if (!shellAbout)
    {
        return EXIT_FAILURE;
    }

    shellAbout(nullptr, DIALOG_TITLE, DIALOG_TEXT, nullptr);

    FreeLibrary(hModule);
    
    return EXIT_SUCCESS;
}
