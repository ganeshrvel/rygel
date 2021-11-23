#define MOZ_UNIFIED_BUILD
#include "src/js/src/frontend/ParserAtom.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/ParserAtom.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/ParserAtom.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/PrivateOpEmitter.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/PrivateOpEmitter.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/PrivateOpEmitter.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/PropOpEmitter.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/PropOpEmitter.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/PropOpEmitter.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/SharedContext.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/SharedContext.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/SharedContext.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/SourceNotes.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/SourceNotes.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/SourceNotes.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/Stencil.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/Stencil.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/Stencil.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif