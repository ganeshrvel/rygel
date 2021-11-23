#!/bin/sh -e

cd $(dirname $0)
ORIG_PATH=$(pwd)

REPO_URL=https://hg.mozilla.org/mozilla-unified
REPO_COMMIT=FIREFOX_91_5_0esr_RELEASE

if test -d ../../bin/MozJS; then
    cd ../../bin/MozJS
    hg pull
else
    mkdir -p ../../bin && cd ../../bin
    hg clone $REPO_URL MozJS
    cd MozJS
fi
hg up $REPO_COMMIT

./mach --no-interactive bootstrap --application-choice js
./mach --no-interactive configure --disable-jemalloc --with-system-zlib --with-intl-api --enable-optimize --disable-tests
./mach --no-interactive build

rm -rf $ORIG_PATH/src $ORIG_PATH/include $ORIG_PATH/unified $ORIG_PATH/system
mkdir -p $ORIG_PATH/src $ORIG_PATH/src/intl/components $ORIG_PATH/include $ORIG_PATH/include/mozilla
rsync -rtc --exclude tests --exclude gtest --exclude shell js/ $ORIG_PATH/src/js/
rsync -rtc --exclude tests --exclude gtest intl/components/ $ORIG_PATH/src/intl/components/
rsync -rtc --exclude tests --exclude gtest memory/ $ORIG_PATH/src/memory/
rsync -rtc --exclude tests --exclude gtest mfbt/ $ORIG_PATH/src/mfbt/
rsync -rtc --exclude tests --exclude gtest mozglue/ $ORIG_PATH/src/mozglue/
cp mozglue/misc/StackWalk_windows.h $ORIG_PATH/include/mozilla/
cp mfbt/WindowsVersion.h $ORIG_PATH/include/mozilla/
rsync -rLc obj-x86_64-pc-linux-gnu/dist/include/ $ORIG_PATH/include/
rsync -rLc obj-x86_64-pc-linux-gnu/dist/system_wrappers/ $ORIG_PATH/system/
rsync -rLmc --include "*/" --include="*.h" --include="*.inc" --exclude "*" obj-x86_64-pc-linux-gnu/js/ $ORIG_PATH/src/js/
rsync -rLmc --include "*/" --include="Unified_*.c*" --exclude "*" obj-x86_64-pc-linux-gnu/ $ORIG_PATH/unified/

find $ORIG_PATH/unified -name "Unified_*.c*" -exec sed -i s+$(pwd)+src+g {} \;
find $ORIG_PATH/unified/mfbt -name "Unified_*.c*" -exec sed -i "1s;^;#define IMPL_MFBT 1\n#undef MOZ_HAS_MOZGLUE\n;" {} \;
find $ORIG_PATH/unified/memory -name "Unified_*.c*" -exec sed -i "1s;^;#define IMPL_MFBT 1\n;" {} \;
(cd $ORIG_PATH && patch -p3 < $ORIG_PATH/../_patches/spidermonkey_001_public_delete_delete.patch)
(cd $ORIG_PATH && patch -p3 < $ORIG_PATH/../_patches/spidermonkey_002_unified_posix_windows_threads.patch)
(cd $ORIG_PATH && patch -p3 < $ORIG_PATH/../_patches/spidermonkey_003_fix_miniz_compatibility.patch)
(cd $ORIG_PATH/system && rm -f ATLCTL.H COMMCTRL.H ExDisp.h Files.h Memory.h Pgenerr.h Process.h QuickDraw.h String.h Strings.h TCHAR.H Types.h Windows.h Winreg.h)
