#!/usr/bin/env bash
# Build the desktop app bundles (AppImage, .deb, .rpm).
#
# Wraps `tauri build` with the environment fixes and the one patch needed on
# modern distros (Arch, anything with gdk-pixbuf >= 2.44 / binutils >= 2.44):
#
#   CI=true                    tauri-cli chokes on CI=1 (parses it as the --ci
#                              flag value; only true/false are valid)
#   NO_STRIP=1                 linuxdeploy's bundled strip predates RELR
#                              sections (.relr.dyn) and aborts on Arch libs
#   APPIMAGE_EXTRACT_AND_RUN=1 AppImages can't mount where FUSE is missing
#                              (VMs, containers); harmless where FUSE exists
#   gtk plugin patch           linuxdeploy-plugin-gtk hard-codes
#                              /usr/lib/gdk-pixbuf-2.0/2.10.0, which no longer
#                              exists with gdk-pixbuf >= 2.44 (loaders are
#                              built-in now). We guard the block in the cached
#                              plugin script. Idempotent.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # repo root
WEB="$HERE/web"
GTK_PLUGIN="${XDG_CACHE_HOME:-$HOME/.cache}/tauri/linuxdeploy-plugin-gtk.sh"
MARKER="puggraph-gdk-pixbuf-guard"

patch_gtk_plugin() {
    [ -f "$GTK_PLUGIN" ] || return 1
    grep -q "$MARKER" "$GTK_PLUGIN" && return 0
    # Already patched by other means (no unguarded copy_tree left)?
    grep -q '^copy_tree "\$gdk_pixbuf_binarydir" "\$APPDIR/"$' "$GTK_PLUGIN" || return 0

    echo "patching cached linuxdeploy-plugin-gtk (gdk-pixbuf >= 2.44 has no loaders dir)..."
    # 1. skip copy_tree when the gdk-pixbuf module dir does not exist
    sed -i 's#^copy_tree "\$gdk_pixbuf_binarydir" "\$APPDIR/"$#[ -n "\$gdk_pixbuf_binarydir" ] \&\& [ -d "\$gdk_pixbuf_binarydir" ] \&\& copy_tree "\$gdk_pixbuf_binarydir" "\$APPDIR/" || true#' "$GTK_PLUGIN"
    # 2. the loaders cache lives under that same (possibly absent) dir
    sed -i 's#^    "\$gdk_pixbuf_query" > "\$APPDIR/\$gdk_pixbuf_cache_file"$#    mkdir -p "\$(dirname "\$APPDIR/\$gdk_pixbuf_cache_file")"; "\$gdk_pixbuf_query" > "\$APPDIR/\$gdk_pixbuf_cache_file" || true#' "$GTK_PLUGIN"
    # 3. don't sed a cache file that was never written
    sed -i 's#^sed -i "s|\$gdk_pixbuf_moduledir/||g" "\$APPDIR/\$gdk_pixbuf_cache_file"$#[ -f "\$APPDIR/\$gdk_pixbuf_cache_file" ] \&\& sed -i "s|\$gdk_pixbuf_moduledir/||g" "\$APPDIR/\$gdk_pixbuf_cache_file" || true#' "$GTK_PLUGIN"
    echo "# $MARKER" >> "$GTK_PLUGIN"
}

build() {
    npm run build --prefix "$WEB"   # frontend (dist/) — tauri's beforeBuildCommand
    env CI=true NO_STRIP=1 APPIMAGE_EXTRACT_AND_RUN=1 \
        npm exec --prefix "$WEB" -- tauri build "$@"
}

# The plugin script is downloaded lazily on the first bundling attempt, so a
# cold cache needs one failing run before it can be patched.
if ! patch_gtk_plugin; then
    build || true                  # populates the cache, then fails on the plugin
    patch_gtk_plugin
fi
build "$@"

echo
echo "bundles at: $WEB/src-tauri/target/release/bundle/"
