#define MOZ_UNIFIED_BUILD
#include "src/js/src/shell/ModuleLoader.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/shell/ModuleLoader.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/shell/ModuleLoader.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/shell/OSObject.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/shell/OSObject.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/shell/OSObject.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/shell/ShellModuleObjectWrapper.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/shell/ShellModuleObjectWrapper.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/shell/ShellModuleObjectWrapper.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/shell/WasmTesting.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/shell/WasmTesting.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/shell/WasmTesting.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/shell/js.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/shell/js.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/shell/js.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/shell/jsoptparse.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/shell/jsoptparse.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/shell/jsoptparse.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif