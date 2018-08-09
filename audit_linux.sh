#!/bin/sh
# Audit Linux Script v2.6 (c) 2001-2018 by Marc Heuse <mh@mh-sec.de>
#
# For all Linux platforms: SuSE, Redhat, Debian, Ubuntu, ...
# and embedded with limited busybox
#
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

#
# CONFIG
#
# where to write the collected data?
TARGET_DIR=/tmp
#TARGET_DIR=`pwd`


#
# No need to change anything below here
#
PATH="/sbin:/usr/sbin:/bin:/usr/bin:$PATH"
HOSTNAME=`hostname`
AUDIT_NAME="AUDIT-$HOSTNAME"
AUDIT_DIR="$TARGET_DIR/$AUDIT_NAME"
OUTFILE="$AUDIT_DIR.tar.gz"

test -e ./qdbus && PATH="$PATH:`pwd`"
test -e ./qdbus && LD_LIBRARY_PATH="$LD_LIBRARY_PATH:`pwd`"
export PATH
export LD_LIBRARY_PATH

FILE_LIST_ETC="/etc/aliases /etc/group /etc/cron* /etc/export* /etc/profile \
 /etc/login* /etc/*ftp* /etc/host* /etc/inittab /etc/issue* /etc/motd \
 /etc/csh* /etc/shells /etc/secur* /etc/sock* /etc/yp* /etc/fstab /etc/snmp* \
 /etc/hosts* /etc/sudoers /etc/default/  /sbin/init.d /etc/pam* /etc/cron* \
 /etc/*conf* /etc/*cfg* /etc/*.d /etc/rc* /etc/pass* /etc/sha* \
 /usr/local/etc/ /etc/mail/ /etc/sendmail.cf  /etc/http* /etc/samba/ \
 /etc/bind /etc/named /etc/postfix /etc/postgresql /etc/mysql /etc/qmail \
 /etc/courier /etc/cups /etc/dhcp* /etc/*ssh*/ssh*conf* /etc/xinetd* \
 /etc/*/*conf /usr/local/etc /etc/squid* /etc/ldap /etc/openldap /etc/squid \
 /etc/rpm /etc/up2date/ /etc/sysconfig /etc/php* /etc/apache* /etc/exim* \
 /etc/apt* /etc/system* /lib/systemd/"

test "`id -u`" -ne 0 && echo "WARNING: Not running as root, a lot of information will not be gathered!"

# Set up a secure directory for gathering data
OLD_UMASK=`umask`
OLD_ENV=`env`
umask 077
set -o noclobber
> "$OUTFILE" || exit 1
if [ -e "$AUDIT_DIR" ]; then
    mv "$AUDIT_DIR" "$AUDIT_DIR".old
fi
mkdir "$AUDIT_DIR" || exit 1
cd "$AUDIT_DIR" || exit 1
set +o noclobber

# Get system performance data before we use the system
df -k > disk.out 2>/dev/null
uptime > uptime.out  2>/dev/null
cat /proc/meminfo > memory.out  2>/dev/null
sar 5 2 > sar.out  2>/dev/null
vmstat > vmstat.out  2>/dev/null
# Process accounting
if [ -d /var/log/sa ] ; then
  tar cf system-act.tar /var/log/sa/ 2>/dev/null
fi
dmesg > dmesg.out 2>/dev/null

# Machine name
uname -a > uname.out  2>/dev/null
# Machine OS and version
cat /etc/*release* >> uname.out  2>/dev/null
# Loaded modules
lsmod >lsmod.out 2>/dev/null
# Mounted file systems
mount > mount.out 2>/dev/null
# RPC services
rpcinfo -p > rpcinfo.out 2>/dev/null
# Exported filesystems
SM=`which showmount 2> /dev/null`
test -n "$SM" && showmount -e > exports.out 2>/dev/null
# Processes
ps auxwww > ps.out 2>/dev/null
# Processes (old Busybox)
ps > ps-old.out 2>/dev/null
# Interfaces
ifconfig -a > ifconfig.out 2>/dev/null
# List of packages
RPM=`which rpm 2>/dev/null`
test -n "$RPM" && rpm -qa > rpm.out 2>/dev/null
DPKG=`which dpkg 2>/dev/null`
test -n "$DPKG" && dpkg -l > dpkg.out 2>/dev/null
test -n "$DPKG" && dpkg --get-selections "*" > dpkg-patches.out 2>/dev/null
OPKG=`which opkg 2>/dev/null`
test -n "$OPKG" && opkg -l > opkg.out 2>/dev/null
PKG=`which pkg-config 2> /dev/null`
test -n "$PKG" && pkg-config --list-all > pkg-config.out 2>/dev/null
# systemctl available? then dump services
SYSTEMCTL=`which systemctl 2> /dev/null`
test -n "$SYSTEMCTL" && systemctl -a > systemctl.out 2>/dev/null
# Patches available (needs to be registered) - only Redhat
if [ -f /etc/sysconfig/rhn/rhn_register ] ; then
  up2date -l > up2date.out 2>/dev/null
else
  echo "No update information available, check patches manually" > up2date.out
fi
if [ -d /etc/apt.d ] ; then
  apt-config dump > apt.out 2> /dev/null
else
  echo "no apt information available" > apt.out
fi
# Chkconfig services
CHK=`which chkconfig 2>/dev/null`
test -n "$CHK" && chkconfig --list >chkconfig.out  2>/dev/null
# Users connected to the system
last -25 > last_25.out  2>/dev/null
last -5 root > last_root.out  2>/dev/null
# X access controls
xhost > xhost.out  2>/dev/null
xauth list >xauth.out  2>/dev/null
# History of user running the audit
history > history.out  2>/dev/null
# Open listeners
netstat -an > netstat-an.out  2>/dev/null
# Routing
netstat -rn > netstat-rn.out  2>/dev/null
# Process-sockets
netstat -anp > netstat-anp.out  2>/dev/null
# Process-sockets 
LSOF=`which lsof 2> /dev/null`
test -n "$LSOF" && lsof -n >lsof.out 2>/dev/null
# Process-sockets
ss -lnp4 > ss.out
ss -lnp6 >> ss.out
# Linux kernel settings
SYSCTL=`which sysctl 2> /dev/null`
test -n "$SYSCTL" && sysctl -a > sysctl.out 2>/dev/null
#kernel vulnerability patches
> vulnerabilities.out
test -d "/sys/devices/system/cpu/vulnerabilities" && {
  for i in /sys/devices/system/cpu/vulnerabilities/* ; do
    echo -n "$i = "
    cat $i
  done > vulnerabilities.out
}
# Shared memory
ipcs -ma > shmem1.out
ipcs -pa > shmem2.out

# Environment and Umask
echo "$OLD_ENV" > env.out
echo "$OLD_UMASK" > umask.out

# IP Filtering 
# For 4.x kernels
nft -n list ruleset >nft.out 2>/dev/null
# For 2.4+ kernels
iptables -nvL >iptables.out 2>/dev/null
ip6tables -nvL >ip6tables.out 2>/dev/null
# For 2.2 kernels
ipchains -L -n -v > ipchains.out 2>/dev/null
# For older kernels
ipfwadm  -L -n -v > ipfwadm.out 2>/dev/null

# Kernel parameters (not all might apply)
# Note: This is maybe too exaggerated (might it introduce issues? (jfs)
# TCP/IP parameters
for i in `find /proc/sys/net/ipv4 -type f | grep -v flush`; do
  echo -n "$i: " >> proc.out
  cat $i >> proc.out  2>/dev/null
  echo "" >> proc.out
done
for i in icmp_echo_ignore_broadcasts icmp_echo_ignore_all tcp_syncookies \
 ip_always_defrag ip_forward ; do
  echo -n "/proc/sys/net/ipv4/$i: " >> proc.out
  cat /proc/sys/net/ipv4/$i >> proc.out  2>/dev/null
  echo "" >> proc.out
done
for i in /proc/sys/net/ipv4/conf/*; do
  for j in accept_redirects accept_source_route rp_filter bootp_relay \
   mc_forwarding log_martians proxy_arp secure_redirects arp_announce \
   arp_ignore send_redirects ; do
    echo -n "$i/$j: " >> proc.out
    cat $i/$j >> proc.out  2>/dev/null
    echo "" >> proc.out
  done
done
for i in /proc/sys/net/ipv6/conf/*; do
  for j in accept_dad accept_ra accept_ra_defrtr accept_ra_pinfo \
   accept_ra_rt_info_max_plen accept_ra_rtr_pref accept_redirects \
   accept_source_route autoconf dad_transmits disable_ipv6 forwarding \
   max_addresses mc_forwarding temp_prefered_lft temp_valid_lft \
   use_tempaddr; do
    echo -n "$i/$j: " >> proc.out
    cat $i/$j >> proc.out  2>/dev/null
    echo "" >> proc.out
  done
done

# Gather configuration data
tar cf etc.tar $FILE_LIST_ETC 2> /dev/null
tar cf var.tar /var/yp /var/nis/data /var/spool/cron 2> /dev/null

# NOTE: If using automounter this will fail (should abort before)
tar cf home.tar /.*bash* /.netrc /.rhosts /.log* /.*csh* /.Xa* \
 /.prof* /home/*/.*bash* /home/*/.netrc /home/*/.rhosts \
 /home/*/.log* /home/*/.*csh* /home/*/.Xa* /home/*/.prof* \
 /root/.*bash* /root/.netrc /root/.rhosts /root/.log* /root/.*csh* \
 /root/.Xa* /root/.prof* 2> /dev/null

find / \( -perm -4000 -o -perm -2000 \) -type f > suid.out 2>/dev/null
find / \( -perm -4000 -o -perm -2000 \) -type f -exec /bin/ls -ld {} \; > find-s_id.out 2>/dev/null
find / -perm -2 '!' -type l -exec /bin/ls -ld {} \; > find-write.out 2>/dev/null

# get kernel config
modprobe configs
tar cf config.tar /proc/config*

# List directories
/bin/ls -al / > ls-root.out 2>/dev/null
# Configuration files
/bin/ls -alR /etc > ls-etc.out 2>/dev/null
# Devices 
/bin/ls -alRL /dev > ls-dev.out 2>/dev/null
# Temporary files
/bin/ls -al /tmp > ls-tmp.out 2>/dev/null
/bin/ls -al /var/tmp > ls-var-tmp.out 2>/dev/null
# Log and Spool files
/bin/ls -alR /var/log /var/adm /var/spool /var/spool/mail > ls-var.out 2>/dev/null
# Extra software
/bin/ls -alR /opt /software /usr/local > ls-software.out 2>/dev/null
# Home directories (comment if this is automouted)
/bin/ls -alRL /root /home > ls-home.out 2>/dev/null
# Kernel files
/bin/ls -alR /vmlin* /boot > ls-boot.out 2>/dev/null

# udev execute
find / -name "*.rules" | xargs grep "RUN=" > udev.out

# DBUS
QDBUS=`which qdbus 2> /dev/null`
TIMEOUT=""
#TIMEOUT=`which timeout 2> /dev/null` # too often TIMEOUT does not work
test -n "$TIMEOUT" && TIMEOUT="timeout -s TERM 10"
test -n "$QDBUS" && for h in "" "--system"; do
  for i in `qdbus $h`; do
    for j in `$TIMEOUT qdbus $h $i 2> /dev/null`; do
      $TIMEOUT qdbus $h $i $j 2> /dev/null | while read LINE; do
        echo "$h $i $j $LINE"
      done
    done
  done
done > dbus.out
test -z "$QDBUS" && echo Error: qdbus is not installed, no DBUS information gathered
test -z "$QDBUS" && > dbus.out
                                 
# Finish up, compress the output
export GZIP=-9
cd "$TARGET_DIR"
tar czf "$OUTFILE" "$AUDIT_NAME"
echo "$OUTFILE" is finished, you may delete "$AUDIT_DIR" now.

exit 0
