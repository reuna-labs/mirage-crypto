#!/bin/sh
set -eu
image=/work/linux-test-tmp.ext4
work_mounted=false
tmp_mounted=false
var_mounted=false
task_loop=
cleanup() {
  if "$var_mounted"; then umount /var/tmp || true; fi
  if "$tmp_mounted"; then umount /tmp || true; fi
  if "$work_mounted"; then umount /work/tmp || true; fi
  if [ -n "$task_loop" ]; then losetup --detach "$task_loop" || true; fi
}
trap cleanup EXIT
trap 'exit 0' INT TERM
for i in $(seq 0 63); do
  test -b /dev/loop$i || mknod /dev/loop$i b 7 $i
done
if [ -n "$(losetup --associated "$image")" ]; then
  echo "Refusing an already attached test image" >&2
  exit 1
fi
task_loop=$(losetup --find --show "$image")
mount -t ext4 -o noatime "$task_loop" /work/tmp
work_mounted=true
mkdir -p /work/tmp/var-tmp
mount --bind /work/tmp /tmp
tmp_mounted=true
mount --bind /work/tmp/var-tmp /var/tmp
var_mounted=true
{
  date -u
  losetup --list --output NAME,BACK-FILE "$task_loop"
  for mount_path in /work/tmp /tmp /var/tmp; do findmnt -T "$mount_path"; done
  df -h /work /work/tmp /
} > /work/logs/native-tmp-mount.log
sleep infinity &
wait "$!"
