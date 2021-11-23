#define MOZ_UNIFIED_BUILD
#ifdef _WIN32
    #include "src/js/src/threading/windows/WindowsThread.cpp"
    #ifdef PL_ARENA_CONST_ALIGN_MASK
    #error "src/js/src/threading/windows/WindowsThread.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
    #undef PL_ARENA_CONST_ALIGN_MASK
    #endif
    #ifdef INITGUID
    #error "src/js/src/threading/windows/WindowsThread.cpp defines INITGUID, so it cannot be built in unified mode."
    #undef INITGUID
    #endif
#else
    #include "src/js/src/threading/posix/PosixThread.cpp"
    #ifdef PL_ARENA_CONST_ALIGN_MASK
    #error "src/js/src/threading/posix/PosixThread.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
    #undef PL_ARENA_CONST_ALIGN_MASK
    #endif
    #ifdef INITGUID
    #error "src/js/src/threading/posix/PosixThread.cpp defines INITGUID, so it cannot be built in unified mode."
    #undef INITGUID
    #endif
#endif
#include "src/js/src/util/AllocPolicy.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/util/AllocPolicy.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/util/AllocPolicy.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/util/AllocationLogging.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/util/AllocationLogging.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/util/AllocationLogging.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/util/CompleteFile.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/util/CompleteFile.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/util/CompleteFile.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/util/DumpFunctions.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/util/DumpFunctions.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/util/DumpFunctions.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/util/NativeStack.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/util/NativeStack.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/util/NativeStack.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif