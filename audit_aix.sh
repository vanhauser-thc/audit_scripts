#!/bin/sh
#
# Audit IBM AIX Script v1.5 (c) 2001-2012 by Marc Heuse <mh@mh-sec.de>
# with additions from Javier Fernandez-Sanguino <jfs@computer.org>
# Audit repository: http://www.mh-sec.de/audit/
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
PATH="/sbin:/usr/sbin:/bin:/usr/bin:$PATH"
HOSTNAME=`hostname`
AUDIT_NAME="AUDIT-$HOSTNAME"
AUDIT_DIR="/tmp/$AUDIT_NAME"
OUTFILE="$AUDIT_DIR.tar"

[ "`id -u`" -ne 0 ] && echo "Not running as root, some information might not be extracted"

FILE_LIST_ETC="/etc/aliases /etc/sendmail.cf /etc/mail /etc/dt /etc/group \
 /etc/cron* /etc/export* /etc/xtab /etc/profile /etc/login* /etc/xtab \
 /etc/*ftp* /etc/host* /etc/inittab /etc/issue* /etc/pam* /etc/secur* /etc/motd \
 /etc/shells /etc/securetty /etc/sock* /etc/yp* /etc/filesystems /etc/hosts* \
 /etc/*/*conf /usr/local/etc \
 /etc/csh* /etc/environment /etc/auto* /etc/uucp/* /etc/pass*"

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

# Extract information from the system
tar cf etc.tar /etc/*conf* /etc/*cfg* /etc/*.d /etc/rc* /etc/tcpip \
 /etc/*ssh*/ssh*conf* /etc/default /etc/security /sbin/rc* \
 $FILE_LIST_ETC 2> /dev/null
tar cf var.tar /var/yp /var/nis/data /var/spool/cron /var/adm/cron 2> /dev/null
tar cf home.tar /.*bash* /.netrc /.rhosts /.log* /.*csh* /.Xa* \
 /.prof* /home/*/.*bash* /home/*/.netrc /home/*/.rhosts \
 /home/*/.log* /home/*/.*csh* /home/*/.Xa* /home/*/.prof* \
 /root/.*bash* /root/.netrc /root/.rhosts /root/.log* /root/.*csh* \
 /root/.Xa* /root/.prof* 2> /dev/null

find / \( -perm -4000 -o -perm -2000 \) -type f -exec /bin/ls -ld {} \; >> find-s_id.out 2>/dev/null
find / -perm -2 '!' -type l -exec /bin/ls -ld {} \; >> find-write.out 2>/dev/null

# List directories
/bin/ls -al / > ls-root.out 2>/dev/null
/bin/ls -alR /etc > ls-etc.out 2>/dev/null
/bin/ls -alRL /dev > ls-dev.out 2>/dev/null
/bin/ls -al /tmp /*/tmp/ > ls-tmp.out 2>/dev/null
/bin/ls -alR /var/log /var/adm /var/spool /var/spool/mail /var/user* > ls-var.out 2>/dev/null
/bin/ls -lL /dev/*rmt* /dev/*floppy* /dev/fd0* /dev/*audio* /dev/*mix* > ls-dev-spec.out 2>/dev/null
/bin/ls -alR /usr/adm /usr/bin/mail/  /usr/*/adm/ > ls-usr.out 2>/dev/null
/bin/ls -alR /opt /software /usr/local > ls-software.out 2>/dev/null
/bin/ls -alRL /home > ls-home.out 2>/dev/null
# Mounted file systems
mount > mount.out 2>/dev/null
# RPC programs
rpcinfo -p > rpcinfo.out 2>/dev/null
# Processes
ps -elf > ps.out
# Patches
instfix -a > instfix.out 2>/dev/null
# System information
uname -a > uname.out 2>/dev/null
oslevel >> uname.out 2>/dev/null
oslevel -r >>uname.out 2>/dev/null
# Users connected to the system
last -25 > last_25.out 2>/dev/null
last -5 root > last_root.out 2>/dev/null
xhost > xhost.out 2>/dev/null
# History of user running the audit
history > history.out 2>/dev/null
# Open listeners
netstat -an > netstat-an.out 2>/dev/null
# Interfaces
netstat -i > netstat-i.out 2>/dev/null
# Routing
netstat -rn > netstat-rn.out 2>/dev/null
# Process-sockets
which lsof >/dev/null 2>/dev/null && lsof -n >lsof.out 2>/dev/null
# Environment and Umask
echo "$OLD_ENV" > env.out 2>/dev/null
echo "$OLD_UMASK" > umask.out 2>/dev/null
# Review TCP/IP configuration:
no -a > no.out 2>/dev/null
# Inet services
inetserv -s -S -X >inet-serv.out 2>/dev/null
hostent -S >hostent.out  2>/dev/null
namerslv -s -I >namesrv.out 2>/dev/null
lssrc -a >lssrc-all.out 2>/dev/null
lssrc -g tcpip >lssrc-tcpip.out 2>/dev/null
lssrc -ls inetd >lssrc-inetd.out 2>/dev/null
lssrc -g nfs >lssrc-nfs.out 2>/dev/null
lsdev -C -c if >lsdev-if.out 2>/dev/null
# Password inconsistencies
which pwdck >/dev/null 2>/dev/null && pwdck -n ALL >pwdck.out 2>/dev/null
which grpck >/dev/null 2>/dev/null && grpck -n ALL >grpck.out 2>/dev/null
# List users
lsuser -f ALL >lsuser.out 2>/dev/null
# Software inventory
lslpp -l > sw-inv.out 2>/dev/null
lslpp -h > sw-inv-host.out 2>/dev/null

cd /tmp
tar cf "$OUTFILE" "$AUDIT_NAME"
compress -c "$OUTFILE" >> "$OUTFILE".Z
/bin/rm -f "$OUTFILE"
echo
echo "$OUTFILE".Z is finished, you may delete "$AUDIT_DIR" now.
