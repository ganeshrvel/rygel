#define MOZ_UNIFIED_BUILD
#include "src/js/src/frontend/AbstractScopePtr.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/AbstractScopePtr.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/AbstractScopePtr.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/AsyncEmitter.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/AsyncEmitter.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/AsyncEmitter.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/BytecodeCompiler.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/BytecodeCompiler.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/BytecodeCompiler.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/BytecodeControlStructures.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/BytecodeControlStructures.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/BytecodeControlStructures.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/BytecodeEmitter.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/BytecodeEmitter.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/BytecodeEmitter.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/BytecodeSection.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/BytecodeSection.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/BytecodeSection.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif