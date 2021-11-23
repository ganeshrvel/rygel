#define MOZ_UNIFIED_BUILD
#include "src/js/src/jit/BitSet.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/jit/BitSet.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/jit/BitSet.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/jit/BytecodeAnalysis.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/jit/BytecodeAnalysis.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/jit/BytecodeAnalysis.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/jit/CacheIR.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/jit/CacheIR.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/jit/CacheIR.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/jit/CacheIRCompiler.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/jit/CacheIRCompiler.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/jit/CacheIRCompiler.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/jit/CacheIRHealth.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/jit/CacheIRHealth.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/jit/CacheIRHealth.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/jit/CacheIRSpewer.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/jit/CacheIRSpewer.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/jit/CacheIRSpewer.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif