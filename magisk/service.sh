#!/system/bin/sh

MODDIR=${0%/*}

while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 1
done

"$MODDIR/ebpf-open" -c "$MODDIR/config.toml" -s "$MODDIR/ebpf-open.log" &
