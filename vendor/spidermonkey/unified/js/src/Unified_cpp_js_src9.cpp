#define MOZ_UNIFIED_BUILD
#include "src/js/src/builtin/streams/WritableStreamDefaultWriter.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/streams/WritableStreamDefaultWriter.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/streams/WritableStreamDefaultWriter.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/streams/WritableStreamOperations.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/streams/WritableStreamOperations.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/streams/WritableStreamOperations.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/streams/WritableStreamWriterOperations.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/streams/WritableStreamWriterOperations.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/streams/WritableStreamWriterOperations.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/ds/Bitmap.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/ds/Bitmap.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/ds/Bitmap.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/ds/LifoAlloc.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/ds/LifoAlloc.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/ds/LifoAlloc.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/ds/MemoryProtectionExceptionHandler.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/ds/MemoryProtectionExceptionHandler.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/ds/MemoryProtectionExceptionHandler.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif