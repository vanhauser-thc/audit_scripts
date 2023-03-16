#!/bin/sh
# Audit HP-UX 9.x / 10.x Script v1.5 (c) 2001-2012 by Marc Heuse <mh@mh-sec.de>
# with additions from Javier Fernandez-Sanguino <jfs@computer.org>
# Source repository: http://www.mh-sec.de/audit/
# Note: This script is for checking the system configuration, NOT for forensic!
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
PATH="/sbin:/usr/sbin:/bin:/usr/bin:/usr/lbin:$PATH"
HOSTNAME=`hostname`
AUDIT_NAME="AUDIT-$HOSTNAME"
AUDIT_DIR="/tmp/$AUDIT_NAME"
OUTFILE="$AUDIT_DIR.tar"

[ "`id`" -ne 0 ] && echo "Not running as root, some information might not be extracted"

FILE_LIST_ETC="/etc/aliases /etc/sendmail.cf /etc/passwd /etc/group \
 /etc/cron* /etc/export* /etc/profile /etc/login* /etc/inittab\
 /etc/*ftp* /etc/host* /etc/inittab /etc/issue* /etc/motd /etc/csh* \
 /etc/shells /etc/securetty /etc/sock* /etc/yp* /etc/SnmpAgent.d/ \
 /etc/*/*conf /usr/local/etc \
 /etc/ntp.conf /etc/fstab /etc/mail /etc/shad* /etc/pam.conf /tcb/auth/files "

OLD_UMASK=`umask`
OLD_ENV=`env`
umask 077
set -o noclobber
> "$OUTFILE" || exit 1
> "$OUTFILE.Z" || exit 1
if [ -e "$AUDIT_DIR" ]; then
    mv "$AUDIT_DIR" "$AUDIT_DIR".old
fi
mkdir "$AUDIT_DIR" || exit 1
cd "$AUDIT_DIR" || exit 1
set +o noclobber

# get performance data
df -k > disk.out 2>/dev/null
bdf >> disk.out 2>/dev/null
uptime > uptime.out 2>/dev/null
swapinfo -t > memory.out  2>/dev/null
sar 5 2 > sar.out 2>/dev/null
vmstat > vmstat.out 2>/dev/null
/etc/dmesg > debug.out 2>/dev/null

# Extract information from the system
tar cf etc.tar /tcb /etc/*conf* /etc/*cfg* /etc/*.d /etc/rc* /etc/httpd \
 /etc/default /etc/security /sbin/init.d /etc/rc* /sbin/rc* /etc/*ssh*/ssh*conf* \
 /etc/mail/sendmail.cf  $FILE_LIST_ETC 2> /dev/null
tar cf var.tar /var/yp /var/nis/data /var/spool/cron /var/adm/cron 2> /dev/null
tar cf usr.tar /usr/spool/cron 2> /dev/null
tar cf tcb.tar /tcb/files 2> /dev/null
tar cf home.tar /.*bash* /.netrc /.rhosts /.log* /.*csh* /.Xa* \
 /.prof* /home/*/.*bash* /home/*/.netrc /home/*/.rhosts \
 /home/*/.log* /home/*/.*csh* /home/*/.Xa* /home/*/.prof* \
 /root/.*bash* /root/.netrc /root/.rhosts /root/.log* /root/.*csh* \
 /root/.Xa* /root/.prof* 2> /dev/null

# Find stuff that might be a problem to the system
# Setuid files
find / \( -perm -4000 -o -perm -2000 \) -type f -exec /bin/ls -ld {} \; > find-s_id.out
# All-Writable stuff
find / -perm -2 '!' -type l -exec /bin/ls -ld {} \; > find-write.out
# List directories
/bin/ls -al / > ls-root.out
/bin/ls -alR /etc > ls-etc.out
/bin/ls -alRL /dev > ls-dev.out
/bin/ls -al /tmp > ls-tmp.out
/bin/ls -alR /var/adm /var/spool /var/mail > ls-var.out
/bin/ls -lL /dev/*rmt* /dev/*floppy* /dev/fd0* /dev/*audio* /dev/*mix* > ls-dev-spec.out 2> /dev/null
/bin/ls -alR /opt /software /usr/local > ls-software.out 2> /dev/null
# Mounted file systems
mount > mount.out
# RPC programs
rpcinfo -p > rpcinfo.out 2>/dev/null
# Processes
ps -ef > ps.out
# Patches
swlist > patch.out  2>/dev/null
# System information
uname -a > uname.out
getprivgrp > hpux-getprivgrp.out  2>/dev/null
# Users connected to the system
last -25 > last_25.out
last -5 root > last_root.out
# History of user running the audit
history > history.out
# Environment and Umask
echo "$OLD_ENV" > env.out
echo "$OLD_UMASK" > umask.out
# Open listeners
netstat -an > netstat-an.out
# Process-sockets
which lsof >/dev/null 2>/dev/null && lsof -n >lsof.out
# Routing
netstat -rn > netstat-rn.out
# Trusted mode
getprdef -r >getprdef.out 2>/dev/null
getprdef -m umaxlntr >>getprdef.out 2>/dev/null

#TODO:
#netune parameters!

cd /tmp
tar cf "$OUTFILE" "$AUDIT_NAME"
compress -c "$OUTFILE" >> "$OUTFILE".Z
/bin/rm -f "$OUTFILE"
echo
echo "$OUTFILE".Z is finished, you may delete "$AUDIT_DIR" now.
