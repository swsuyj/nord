#!/bin/bash

echo -n "What is the version? "
read ver
echo
tar_dest=/tmp/nord-$ver


# Set up build environment
echo "Setting up"
rpmdev-setuptree
mkdir -p $tar_dest
cp nord $tar_dest
cp LICENSE $tar_dest
cp -r doc $tar_dest

tar -cvzf $tar_dest.tar.gz $tar_dest
mv $tar_dest.tar.gz $HOME/rpmbuild/SOURCES

cp nord.spec $HOME/rpmbuild/SPECS


# Build
echo "Building"
prevdir=$(pwd)
cd $HOME/rpmbuild/SPECS
rpmbuild -bs nord.spec
cp $HOME/rpmbuild/SRPMS/nord-$ver.src.rpm $prevdir
mkdir -p $prevdir/build
cd $prevdir


[[ $1 != "--cleanup" ]] && exit 0
# Clean up
echo "Cleaning up"
rm -rf $HOME/rpmbuild
