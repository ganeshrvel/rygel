#define MOZ_UNIFIED_BUILD
#include "src/js/src/builtin/streams/MiscellaneousOperations.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/streams/MiscellaneousOperations.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/streams/MiscellaneousOperations.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/streams/PipeToState.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/streams/PipeToState.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/streams/PipeToState.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/streams/PullIntoDescriptor.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/streams/PullIntoDescriptor.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/streams/PullIntoDescriptor.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/streams/QueueWithSizes.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/streams/QueueWithSizes.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/streams/QueueWithSizes.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/streams/QueueingStrategies.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/streams/QueueingStrategies.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/streams/QueueingStrategies.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/streams/ReadableStream.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/streams/ReadableStream.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/streams/ReadableStream.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif