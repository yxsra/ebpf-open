#!/system/bin/sh

SKIPUNZIP=1

if [ "$ARCH" != "arm64" ]; then
    abort "This module only supports arm64 devices"
fi

ui_print "- Installing eBPF Open Monitor"

unzip -o "$ZIPFILE" module.prop service.sh ebpf-open config.toml -d "$MODPATH"

set_perm "$MODPATH/ebpf-open" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/config.toml" 0 0 0644

ui_print "- Done"
