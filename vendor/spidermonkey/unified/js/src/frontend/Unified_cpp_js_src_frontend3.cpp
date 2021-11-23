#define MOZ_UNIFIED_BUILD
#include "src/js/src/frontend/IfEmitter.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/IfEmitter.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/IfEmitter.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/JumpList.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/JumpList.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/JumpList.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/LabelEmitter.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/LabelEmitter.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/LabelEmitter.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/LexicalScopeEmitter.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/LexicalScopeEmitter.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/LexicalScopeEmitter.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/NameFunctions.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/NameFunctions.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/NameFunctions.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/NameOpEmitter.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/NameOpEmitter.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/NameOpEmitter.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif