#define MOZ_UNIFIED_BUILD
#include "src/js/src/vm/NativeObject.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/vm/NativeObject.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/vm/NativeObject.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/vm/OffThreadPromiseRuntimeState.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/vm/OffThreadPromiseRuntimeState.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/vm/OffThreadPromiseRuntimeState.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/vm/OffThreadScriptCompilation.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/vm/OffThreadScriptCompilation.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/vm/OffThreadScriptCompilation.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/vm/PIC.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/vm/PIC.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/vm/PIC.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/vm/PlainObject.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/vm/PlainObject.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/vm/PlainObject.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/vm/Printer.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/vm/Printer.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/vm/Printer.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif