// dllMemcpyMon.h
#ifdef DLLMEMCPYMON_EXPORTS
#define DLLMEMCPYMON_API __declspec(dllexport)
#else
#define DLLMEMCPYMON_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

DLLMEMCPYMON_API void* __cdecl My_memcpy(void* dest, const void* src, size_t count);
DLLMEMCPYMON_API void __cdecl setBufPtr(unsigned char* ptr);

#ifdef __cplusplus
}
#endif

DLLMEMCPYMON_API extern unsigned char* bufPtr;