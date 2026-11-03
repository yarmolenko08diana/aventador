"""Группы API-функций для правил индикаторов.

Имена указаны без суффиксов A/W: при сравнении суффикс у импортированной функции отбрасывается.
"""

INJECTION = {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "SetThreadContext", "QueueUserAPC",
    "NtWriteVirtualMemory", "RtlCreateUserThread",
}
ANTIDEBUG = {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"}
ANTIDEBUG_STRONG = {"CheckRemoteDebuggerPresent"}  # достаточно одной этой функции
KEYLOG = {"SetWindowsHookEx", "GetAsyncKeyState"}
DYNLOAD_LOAD = {"LoadLibrary", "LoadLibraryEx", "LdrLoadDll"}
DYNLOAD_RESOLVE = {"GetProcAddress", "LdrGetProcedureAddress"}
DOWNLOAD = {"URLDownloadToFile", "URLDownloadToCacheFile", "InternetOpenUrl", "WinHttpOpen"}
SERVICE = {"CreateService"}


def normalize(name: str) -> str:
    """CreateRemoteThread, LoadLibraryExW -> LoadLibraryEx, ordinal123 остаётся как есть."""
    if len(name) > 1 and name[-1] in "AW" and name[-2].islower():
        return name[:-1]
    return name
