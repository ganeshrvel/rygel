#define MOZ_UNIFIED_BUILD
#include "src/js/src/debugger/DebugScript.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/debugger/DebugScript.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/debugger/DebugScript.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/debugger/Debugger.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/debugger/Debugger.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/debugger/Debugger.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/debugger/DebuggerMemory.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/debugger/DebuggerMemory.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/debugger/DebuggerMemory.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/debugger/Environment.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/debugger/Environment.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/debugger/Environment.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/debugger/Frame.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/debugger/Frame.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/debugger/Frame.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/debugger/NoExecute.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/debugger/NoExecute.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/debugger/NoExecute.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif