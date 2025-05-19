# first argument is link to orange dir
meson setup build --cross-file ci/orange.cross-file --wipe --prefix=$1/initrd/usr
cd build
ninja install 
cd ..