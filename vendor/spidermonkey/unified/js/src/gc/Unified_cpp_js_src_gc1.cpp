#define MOZ_UNIFIED_BUILD
#include "src/js/src/gc/Marking.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/gc/Marking.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/gc/Marking.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/gc/Memory.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/gc/Memory.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/gc/Memory.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/gc/Nursery.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/gc/Nursery.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/gc/Nursery.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/gc/Pretenuring.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/gc/Pretenuring.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/gc/Pretenuring.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/gc/PublicIterators.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/gc/PublicIterators.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/gc/PublicIterators.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/gc/RootMarking.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/gc/RootMarking.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/gc/RootMarking.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif