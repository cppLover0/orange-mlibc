# first argument is link to orange dir

git clone https://github.com/torvalds/linux.git --depth=1
cd linux
make headers_install ARCH=x86_64 INSTALL_HDR_PATH=$1/initrd/usr
cd ..


meson setup build --cross-file ci/orange.cross-file --wipe --prefix=$1/initrd/usr -Dlinux_kernel_headers=$1/initrd/usr/include
cd build
ninja -j$(nproc)
ninja install 
cd ..