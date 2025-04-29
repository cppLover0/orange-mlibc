# first argument is link to orange dir
meson setup build --cross-file ci/orange.cross-file --wipe
cd build
ninja
cp -rf ./*.so sysdeps/orange/crt0.o sysdeps/orange/crti.o sysdeps/orange/crtn.o ~/opt/cross/x86_64-orange/lib
cp -rf ./*.so sysdeps/orange/crt0.o sysdeps/orange/crti.o sysdeps/orange/crtn.o $1/initrd/usr/lib
cd ..