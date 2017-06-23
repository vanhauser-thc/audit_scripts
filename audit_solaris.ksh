#!/usr/bin/ksh
# #!/bin/sh <- does not support noclobber mode
#
# Audit Sun Solaris Script v1.7 (c) 2001-2012
# by Marc Heuse <mh@mh-sec.de>
# with additions from Frank Dick <fd(at)digitalcrime(dot)org>
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
# Notes (jfs): This script sometimes core dumps in Solaris 8. It should
# be analised to determine where the issue is.
#
PATH="/sbin:/usr/sbin:/bin:/usr/bin:/usr/ucb:$PATH"
HOSTNAME=`hostname`
AUDIT_NAME="AUDIT-$HOSTNAME"
AUDIT_DIR="/tmp/$AUDIT_NAME"
OUTFILE="$AUDIT_DIR.tar"

echo "Warning: if the system is not correctly set up, e.g. automounter \
points are still there, but the automounter service is not running, the \
script might/will hang for the find commands."
echo

OLD_UMASK=`umask`
OLD_ENV=`env`
umask 077
set -o noclobber
> "$OUTFILE" || exit 1
> "$OUTFILE.Z" || exit 1
set +o noclobber
if [ -e "$AUDIT_DIR" ]; then
    mv "$AUDIT_DIR" "$AUDIT_DIR".old
fi
mkdir "$AUDIT_DIR" || exit 1
cd "$AUDIT_DIR" || exit 1

ID=`id -u 2> /dev/null`
if [ -z "$ID" ]; then
  ID=`/usr/xpg4/bin/id -u 2> /dev/null`
fi
[ "$ID" -ne 0 ] && echo "Not running as root, some information might not be extracted"

# get performance data
df -k > disk.out 2>/dev/null
uptime > uptime.out 2>/dev/null
prtconf > memory.out  2>/dev/null
vmstat > vmstat.out 2>/dev/null
sar 5 2 > sar.out 2>/dev/null

# get version information
cat /etc/release > release.out 2>/dev/null

# Extract information from the system
tar cf etc.tar /etc/*conf* /etc/*cfg* /etc/*.d /etc/rc* /sbin/rc* \
 /etc/default /etc/dfs /etc/inet /etc/security /etc/*ssh*/ssh*conf* \
 /etc/aliases /etc/sendmail.cf /etc/group /etc/users_attr \
 /etc/cron* /etc/export* /etc/profile /etc/login* /etc/.login /etc/logout  \
 /etc/*ftp* /etc/host* /etc/inittab /etc/issue* /etc/motd /etc/csh* \
 /etc/shells /etc/securetty /etc/sock* /etc/system* /etc/yp* /usr/local/etc/*  \
 /etc/auto* /etc/dumpdates /etc/ethers /etc/vfstab /etc/rmtab /etc/vold.conf \
 /etc/pam* /etc/ttydefs /etc/nsswitch.conf /etc/resolv.conf /etc/printers.conf \
 /etc/rpcsec /etc/snmp /etc/dmi /etc/dhcp /etc/cron.d /etc/nfs /etc/nfssec.conf \
 /etc/mail /etc/apache /etc/rpld.conf /etc/dtconfig /etc/named.conf /etc/shad* \
 /etc/netgroups /etc/hosts.* /etc/X*hosts /etc/ppp /etc/rpcsec /etc/pass* \
 /etc/*/*conf /usr/local/etc /etc/ftpd/ftpusers /etc/ftpusers /etc/ipf \
 /etc/hostname* /etc/netconfig /etc/nodename /etc/defaultrouter /etc/uucp/* 2> /dev/null

tar cf var.tar /var/yp /var/nis/data /var/spool/cron 2> /dev/null

# NOTE: If using automounter this will fail (should abort before)
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
/bin/ls -alRL /dev /devices > ls-dev.out 2>/dev/null
/bin/ls -al /tmp /var/tmp /usr/tmp > ls-tmp.out 2>/dev/null
/bin/ls -alR /var/log /var/adm /var/spool /var/audit > ls-var.out 2>/dev/null
/bin/ls -lL /dev/*rmt* /dev/*floppy* /dev/fd0* /dev/*audio* /dev/*mix* > ls-dev-spec.out 2>/dev/null
/bin/ls -alR /opt /software /usr/local > ls-software.out 2>/dev/null
/bin/ls -alRL /home /root > ls-home.out 2>/dev/null
# Mounted file systems
mount > mount.out 2>/dev/null
# RPC programs
rpcinfo -p > rpcinfo.out 2>/dev/null
# Processes
ps -elf > ps.out 2>/dev/null
showrev -a > showrev.out 2>/dev/null
# Installed software (through the package system)
pkginfo -l > pkginfo-l.out 2>/dev/null
pkginfo -x > pkginfo-x.out 2>/dev/null
# Patches
patchadd -p > patchadd.out 2>/dev/null
pkgchk > pkgchk.out 2>/dev/null
# System information
uname -a > uname.out 2>/dev/null
# system crontabs
crontab -l sys > crontab.out 2>/dev/null
crontab -l root >> crontab.out 2>/dev/null
# audit and security config
auditconfig -getcond > auditconfig.out 2>/dev/null
consadm -p > consadm.out 2>/dev/null
digest -l > digest.out 2>/dev/null
pkginfo SUNWbart > bart.out 2>/dev/null
svcs ipfilter > svcsipfilter.out 2>/dev/null
# Users connected to the system
last -25 > last_25.out 2>/dev/null
last -5 root > last_root.out 2>/dev/null
# Xauthorities
xauth list >xauth.out 2>/dev/null
eeprom security-mode > eeprom.out 2>/dev/null
# History of user running the audit
history > history.out 2>/dev/null
# Open listeners
netstat -an > netstat-an.out 2>/dev/null
# Interfaces
netstat -i > netstat-i.out 2>/dev/null
# Routing
netstat -rn > netstat-rn.out 2>/dev/null
# Process-sockets
which lsof >/dev/null 2>/dev/null && lsof -n > lsof.out 2>/dev/null
pfiles `ptree | awk '{print $1}'` 2> /dev/null | egrep '^[0-9]|port:' > lsof2.out
# Environment and Umask
echo "$OLD_ENV" > env.out 2>/dev/null
echo "$OLD_UMASK" > umask.out 2>/dev/null
# Services and diagnostics
svcs -a > svcs.out 2>/dev/null
prtdiag -v >> env.out 2>/dev/null

# Definition of shared libraries (Solaris 8 and later)
crle -v >crl.out 2>/dev/null

# Solaris 10+, zone and role stuff
#if [ "`uname -r`" = "5.10" -o "`uname -r`" = "5.11" -o "`uname -r`" = "5.12" ] ; then
# I should be OK to execute these always, even if < 5.10
  /usr/sbin/zoneadm list -cv > zoneadm-cv.out 2>/dev/null
  /usr/bin/svcs -a > svcs.out 2>/dev/null
  /usr/bin/roles > roles.out 2>/dev/null
  /usr/bin/coreadm > coreadm.out 2>/dev/null
  /usr/sbin/routeadm > routeadm.out 2>/dev/null
  /usr/sbin/inetadm > inetadm.out 2>/dev/null
  /usr/sbin/pkgchk -n > pkgchk-n.out 2>/dev/null
  /usr/sbin/pmadm -l > pmadm.out 2>/dev/null
  /usr/bin/logins -p > loginsp.out 2>/dev/null
  /usr/bin/logins -a > loginsa.out 2>/dev/null
#fi

# Kernel modules
modinfo >modinfo.out 2>/dev/null
# Ndd parameters
# IP
for i in ip_forwarding ip_forward_src_routed ip_respond_to_timestamp \
         ip_respond_to_timestamp_broadcast ip_ignore_redirect ip6_strict_dst_multihoming \
         ip_strict_dst_multihoming ip_forward_directed_broadcasts \
         ip_respond_to_echo_broadcast ip_respond_to_address_mask_broadcast \
         ip6_forward_src_routed  ip6_respond_to_echo_multicast  ip_icmp_err_interval \
         ip_ire_arp_interval ip_ire_flush_interval ip_strict_dst_multihoming \
         ip_send_redirects ip6_forwarding ip6_send_redirects ip6_ignore_redirect; do 
    echo "$i: " >> ndd.out 
    ndd /dev/ip "$i" >> ndd.out 2>/dev/null
    echo "" >> ndd.out
done
# ARP
for i in arp_cleanup_interval; do
    echo "$i: " >> ndd.out
    ndd /dev/arp "$i" >> ndd.out 2>/dev/null
    echo "" >> ndd.out
done
# TCP
for i in tcpip_abort_cinterval tcp_conn_req_max_q tcp_conn_req_max_q0 tcp_strong_iss \
   tcp_extra_priv_ports tcp_time_wait_interval tcp_ip_abort_cinterval \
   tcp_rev_src_routes ; do
    echo "$i: " >> ndd.out
    ndd /dev/tcp "$i" >> ndd.out 2>/dev/null
    echo "" >> ndd.out
done

# Note: xhost might block sometimes (when X11 running and no display)
xhost > xhost.out 2> /dev/null 2>/dev/null

# PCA
uname -a > pca-uname.out 2> /dev/null
showrev -p > pca-showrev.out 2> /dev/null
pkginfo -x > pca-pkginfo.out 2> /dev/null
patchadd -p > pca-patchadd.out 2> /dev/null
# http://www.par.univie.ac.at/solaris/pca/

cd /tmp
tar cf "$OUTFILE" "$AUDIT_NAME"
compress -c "$OUTFILE" >> "$OUTFILE".Z
/bin/rm -f "$OUTFILE"
echo
echo "$OUTFILE".Z is finished, you may delete "$AUDIT_DIR" now.
