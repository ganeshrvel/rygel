#define IMPL_MFBT 1
#define MOZ_UNIFIED_BUILD
#include "src/memory/mozalloc/mozalloc.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/memory/mozalloc/mozalloc.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/memory/mozalloc/mozalloc.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/memory/mozalloc/mozalloc_oom.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/memory/mozalloc/mozalloc_oom.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/memory/mozalloc/mozalloc_oom.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif