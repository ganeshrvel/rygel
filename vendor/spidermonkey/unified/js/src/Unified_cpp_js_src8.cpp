#define MOZ_UNIFIED_BUILD
#include "src/js/src/builtin/streams/ReadableStreamReader.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/streams/ReadableStreamReader.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/streams/ReadableStreamReader.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/streams/StreamAPI.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/streams/StreamAPI.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/streams/StreamAPI.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/streams/TeeState.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/streams/TeeState.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/streams/TeeState.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/streams/WritableStream.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/streams/WritableStream.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/streams/WritableStream.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/streams/WritableStreamDefaultController.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/streams/WritableStreamDefaultController.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/streams/WritableStreamDefaultController.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/streams/WritableStreamDefaultControllerOperations.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/streams/WritableStreamDefaultControllerOperations.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/streams/WritableStreamDefaultControllerOperations.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif