# first argument is link to orange dir

meson setup build --cross-file ci/orange.cross-file --wipe --prefix=$1/initrd/usr -Dlinux_kernel_headers=$1/initrd/usr/include -Ddefault_library=both
cd build
ninja -j$(nproc)
ninja install 
cd ..