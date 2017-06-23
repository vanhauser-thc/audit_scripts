# audit_scripts
Scripts to gather system configuration information for offline/remote auditing

The audit scripts are a set of scripts intented to be run in systems
to recover useful information for them. The information recovered
should be sufficient to do a "white box" analysis of the system,
with the exception of service configuration files that are in unusual
locations.

The suite of scripts is made of simple shell scripts (and a batch
file for Windows) that will extract the relevant information from
the system (installed software and patches, permissions,
TCP/IP listeners, processes, etc.) and allow you to review
that information manually and fill in the appropriate checklist.

The audit scripts have been tested on AIX, Debian GNU/Linux, Ubuntu Linux,
Red Hat Linux, SuSE Linux, HPUX, Solaris and Windows.

Please note that the Oracle and Windows scripts are incomplete at the moment.
