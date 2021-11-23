#define MOZ_UNIFIED_BUILD
#include "src/js/src/proxy/SecurityWrapper.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/proxy/SecurityWrapper.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/proxy/SecurityWrapper.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/proxy/Wrapper.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/proxy/Wrapper.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/proxy/Wrapper.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/threading/Mutex.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/threading/Mutex.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/threading/Mutex.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/threading/ProtectedData.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/threading/ProtectedData.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/threading/ProtectedData.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/threading/Thread.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/threading/Thread.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/threading/Thread.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#ifdef _WIN32
    #include "src/js/src/threading/windows/CpuCount.cpp"
    #ifdef PL_ARENA_CONST_ALIGN_MASK
    #error "src/js/src/threading/windows/CpuCount.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
    #undef PL_ARENA_CONST_ALIGN_MASK
    #endif
    #ifdef INITGUID
    #error "src/js/src/threading/windows/CpuCount.cpp defines INITGUID, so it cannot be built in unified mode."
    #undef INITGUID
    #endif
#else
    #include "src/js/src/threading/posix/CpuCount.cpp"
    #ifdef PL_ARENA_CONST_ALIGN_MASK
    #error "src/js/src/threading/posix/CpuCount.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
    #undef PL_ARENA_CONST_ALIGN_MASK
    #endif
    #ifdef INITGUID
    #error "src/js/src/threading/posix/CpuCount.cpp defines INITGUID, so it cannot be built in unified mode."
    #undef INITGUID
    #endif
#endif