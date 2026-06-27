#!/bin/bash
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
rm -f *.dmg

mkdir -p src
echo "hello hfs+" > src/test.txt

# HFS+ read-write (UDRW)
hdiutil create -size 640k -fs HFS+ -volname "TestData" -srcfolder src "$DIR/tmp1"
hdiutil convert "$DIR/tmp1.dmg" -format UDRW -ov -o "$DIR/hfs_plus_udrw.dmg"

# HFS+ compressed (UDZO)
hdiutil create -size 640k -fs HFS+ -volname "TestData" -srcfolder src "$DIR/tmp2"
hdiutil convert "$DIR/tmp2.dmg" -format UDZO -ov -o "$DIR/hfs_plus_udzo.dmg"

# HFS+ read-only (UDRO)
hdiutil create -size 640k -fs HFS+ -volname "TestData" -srcfolder src "$DIR/tmp3"
hdiutil convert "$DIR/tmp3.dmg" -format UDRO -ov -o "$DIR/read_only.dmg"

# HFS+ encrypted (AES-256)
hdiutil create -size 640k -fs HFS+ -volname "TestData" -encryption AES-256 -passphrase test123 -srcfolder src "$DIR/encrypted.dmg"

# APFS read-write (UDRW)
hdiutil create -size 2m -fs APFS -volname "TestData" -srcfolder src "$DIR/tmp4"
hdiutil convert "$DIR/tmp4.dmg" -format UDRW -ov -o "$DIR/apfs_udrw.dmg"

# APFS read-only (UDRO)
hdiutil create -size 2m -fs APFS -volname "TestData" -srcfolder src "$DIR/tmp5"
hdiutil convert "$DIR/tmp5.dmg" -format UDRO -ov -o "$DIR/apfs_readonly.dmg"

# APFS encrypted (AES-256)
hdiutil create -size 2m -fs APFS -volname "TestData" -encryption AES-256 -passphrase test123 -srcfolder src "$DIR/apfs_encrypted.dmg"

rm -rf "$DIR/src" "$DIR"/tmp*.dmg
ls -lh "$DIR"/*.dmg
