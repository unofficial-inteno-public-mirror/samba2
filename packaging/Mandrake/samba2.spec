%define ver 2.2.7a
%define rel 4mdk
%define vscanver 0.3.1

# 2.2.4 and 1 replace by samba-team at release
%define pversion 2.2.12
%define prelease 1
# For testing this setup:
#%define pversion1 2.2.5
#%define prelease1 %(date +%Y%m%d)

#Check to see if p(version|release) has been replaced (1 if replaced)
%define have_pversion %(if [ "%pversion" = `echo "pversion" |tr '[:lower:]' '[:upper:]'` ];then echo 0; else echo 1; fi)
%define have_prelease %(if [ "%prelease" = `echo "prelease" |tr '[:lower:]' '[:upper:]'` ];then echo 0; else echo 1; fi)

# We might have a alpha-/beta-/pre-/rc-release:
%define have_pre %(echo %pversion|awk '{p=0} /[a-z,A-Z][a-z,A-Z]/ {p=1} {print p}')
%if %have_pre
%define pre_ver %(perl -e '$name="%pversion"; print ($name =~ /(.*?)[a-z]/);')
%define pre_pre %(echo %pversion|sed -e 's/%pre_ver//g')
%endif


# Check to see if we are running a build from a tarball release from samba.org
# (%have_pversion) If so, disable vscan, unless explicitly requested
# (--with vscan).
%define build_vscan 1
%if %have_pversion
%define build_vscan 0
%{?_with_vscan: %define build_vscan 1}
%endif

# We now do detection of the Mandrake release we are building on:
#%define build_cooker %(if [ `awk '{print $3}' /etc/mandrake-release` = "Cooker" ];then echo 1; else echo 0; fi)
#%define build_cooker %(if [[ `cat /etc/mandrake-release|grep Cooker` ]];then echo 1; else echo 0; fi)
%define build_mdk91 %(if [ `awk '{print $4}' /etc/mandrake-release` = 9.1 ];then echo 1; else echo 0; fi)
%define build_mdk90 %(if [ `awk '{print $4}' /etc/mandrake-release` = 9.0 ];then echo 1; else echo 0; fi)
%define build_mdk83 %(if [ `awk '{print $4}' /etc/mandrake-release` = 8.3 ];then echo 1; else echo 0; fi)
%define build_mdk82 %(if [ `awk '{print $4}' /etc/mandrake-release` = 8.2 ];then echo 1; else echo 0; fi)
%define build_mdk81 %(if [ `awk '{print $4}' /etc/mandrake-release` = 8.1 ];then echo 1; else echo 0; fi)
%define build_mdk80 %(if [ `awk '{print $4}' /etc/mandrake-release` = 8.0 ];then echo 1; else echo 0; fi)
%define build_mdk72 %(if [ `awk '{print $4}' /etc/mandrake-release` = 7.2 ];then echo 1; else echo 0; fi)
%define build_non_default 0

# Default options
%define build_acl 	1
%define build_winbind 	1
%define build_wins 	1
%define build_ldap 	0
%define build_scanners	0

# Set defaults for each version
%if %build_mdk91
%define build_ldap 0
%endif

%if %build_mdk90
%define build_ldap 0 
%endif

%if %build_mdk83
%define build_ldap 0
%endif

%if %build_mdk82
%define build_ldap 0
%endif

%if %build_mdk81
%define build_winbind 0
%define build_wins 0
%define build_ldap 0
%endif

%if %build_mdk80
%define build_acl 0
%define build_winbind 0
%define build_wins 0
%define build_ldap 0
%endif

%if %build_mdk72
%define build_acl 0
%define build_winbind 0
%define build_wins 0
%define build_ldap 0
%endif

# Allow commandline option overrides (borrowed from Vince's qmail srpm):
# To use it, do rpm [-ba|--rebuild] --with 'xxx'
# Check if the rpm was built with the defaults, otherwise we inform the user
%{?_with_acl: %{expand: %%define build_acl 1}}
%{?_with_acl: %{expand: %%define build_non_default 1}}
%{?_without_acl: %{expand: %%define build_acl 0}}
%{?_without_acl: %{expand: %%define build_non_default 1}}
%{?_with_winbind: %{expand: %%global build_winbind 1}}
%{?_with_winbind: %{expand: %%define build_non_default 1}}
%{?_without_winbind: %{expand: %%global build_winbind 0}}
%{?_without_winbind: %{expand: %%define build_non_default 1}}
%{?_with_wins: %{expand: %%global build_wins 1}}
%{?_with_wins: %{expand: %%define build_non_default 1}}
%{?_without_wins: %{expand: %%global build_wins 0}}
%{?_without_wins: %{expand: %%define build_non_default 1}}
%{?_with_ldap: %{expand: %%global build_ldap 1}}
%{?_with_ldap: %{expand: %%define build_non_default 1}}
%{?_without_ldap: %{expand: %%global build_ldap 0}}
%{?_without_ldap: %{expand: %%define build_non_default 1}}
%{?_with_scanners: %{expand: %%define build_scanners 1}}
%{?_with_scanners: %{expand: %%define build_non_default 1}}

# As if that weren't enough, we're going to try building with antivirus
# support as an option also
%define build_fprot 0
%define build_kaspersky 0
%define build_mks 0
%define build_openantivirus 0
%define build_sophos 0
%define build_symantec 0
%define build_trend 0
%if %build_vscan && %build_scanners
#These can be enabled here by default
# (kaspersky requires their library present)
%define build_fprot     1
%define build_mks       1
%define build_openantivirus    1
%define build_sophos    1
%define build_trend     1
%endif
%if %build_vscan
%{?_with_fprot: %{expand: %%global build_fprot 1}}
%{?_with_kaspersky: %{expand: %%global build_kaspersky 1}}
%{?_with_mks: %{expand: %%global build_mks 1}}
%{?_with_openav: %{expand: %%global build_openantivirus 1}}
%{?_with_sophos: %{expand: %%global build_sophos 1}}
#%{?_with_symantec: %{expand: %%global build_symantec 1}}
%{?_with_trend: %{expand: %%global build_trend 1}}
%global vscandir samba-vscan-%{vscanver}
%endif
%global vfsdir examples.bin/VFS

#Workaround missing macros in 8.x:
%{!?perl_vendorlib: %{expand: %%global perl_vendorlib %{perl_sitearch}/../}}

Summary: Samba SMB server.
Name: samba
%if %have_pversion && %have_pre
Version: %{pre_ver}
%define source_ver %{pversion}
%endif
%if %have_pversion && !%have_pre
Version: %{pversion}
%define source_ver %{pversion}
%endif
%if !%have_pversion
Version: %{ver}
%define source_ver %{ver}
%endif
%if %have_prelease && !%have_pre
Release: 1.%{prelease}mdk
%endif
%if %have_prelease && %have_pre
Release: 1.0.%{pre_pre}.%{prelease}mdk
%endif
%if !%have_prelease
Release: %{rel}
%endif
License: GPL
URL: http://www.samba.org
Group: System/Servers
Source: ftp://samba.org/pub/samba/samba-%{source_ver}.tar.bz2
Source1: samba.log
Source2: mount.smb
Source3: samba.xinetd
Source4: swat_48.xpm.bz2
Source5: swat_32.xpm.bz2
Source6: swat_16.xpm.bz2
Source7: README.%{name}-mandrake-rpm
%if %build_vscan
Source8: samba-vscan-%{vscanver}.tar.bz2
%endif
Source10: samba-print-pdf.sh.bz2
Patch1: smbw.patch.bz2
Patch2: samba-2.2.0-gawk.patch.bz2
Patch3: samba-2.2.0-buildroot.patch.bz2
Patch4: smbmount-sbin.patch.bz2
Patch5: samba-2.2.5-gp-reloc-fix.patch.bz2
Patch6: samba-2.2.7a-smbldaptools-paths.patch.bz2
%if !%have_pversion
# Version specific patches: current version
Patch101: samba-2.2.7a-smbtar-large-file-fix.patch.bz2
Patch102: samba-2.2.7a-smbclient-large-file-fix.patch.bz2
Patch103: samba-2.2.7a-ldap-rebind.patch.bz2
Patch104: samba-2.2.7a-mandrake-packaging.patch.bz2
Patch105: samba-2.2.6-smbumount_lazy.patch.bz2
%else
# Version specific patches: upcoming version
%endif
# Limbo patches (applied to prereleases, but not preleases, ie destined for 
# samba CVS)
%if %have_pversion && %have_pre
%endif
Requires: pam >= 0.64, samba-common = %{version}
BuildRequires: pam-devel autoconf readline-devel libldap2-devel popt-devel
%if %build_acl
BuildRequires: libacl-devel
%endif
%if %build_mdk72
BuildRequires: cups-devel
%else
BuildRequires: libcups-devel
%endif
#%if %build_ldap
#BuildRequires: libldap-devel
#%endif
BuildRoot: %{_tmppath}/%{name}-root
Prefix: /usr
Prereq: /sbin/chkconfig /bin/mktemp /usr/bin/killall
Prereq: fileutils sed /bin/grep

%description
Samba provides an SMB server which can be used to provide
network services to SMB (sometimes called "Lan Manager")
clients, including various versions of MS Windows, OS/2,
and other Linux machines. Samba also provides some SMB
clients, which complement the built-in SMB filesystem
in Linux. Samba uses NetBIOS over TCP/IP (NetBT) protocols
and does NOT need NetBEUI (Microsoft Raw NetBIOS frame)
protocol.

Samba-2.2 features working NT Domain Control capability and
includes the SWAT (Samba Web Administration Tool) that
allows samba's smb.conf file to be remotely managed using your
favourite web browser. For the time being this is being
enabled on TCP port 901 via xinetd. SWAT is now included in
it's own subpackage, samba-swat.

Users are advised to use Samba-2.2 as a Windows NT4
Domain Controller only on networks that do NOT have a Windows
NT Domain Controller. This release does NOT as yet have
Backup Domain control ability.

Please refer to the WHATSNEW.txt document for fixup information.
This binary release includes encrypted password support.

Please read the smb.conf file and ENCRYPTION.txt in the
docs directory for implementation details.

%if %build_non_default
WARNING: This RPM was built with command-line options. Please
see README.%{name}-mandrake-rpm in the documentation for
more information.
%endif

%if %build_ldap
%package server-ldap
Summary: Samba (SMB) server programs with LDAP (only) support
Obsoletes: samba-server
Provides: samba-server
Requires: samba-common-ldap = %{version}
%else
%package server
Summary: Samba (SMB) server programs.
Obsoletes: samba-server-ldap
Requires: samba-common = %{version}
%endif
Group: Networking/Other
Provides: samba
Obsoletes: samba

%if %build_ldap
%description server-ldap
%else
%description server
%endif
Samba-server provides a SMB server which can be used to provide
network services to SMB (sometimes called "Lan Manager")
clients. Samba uses NetBIOS over TCP/IP (NetBT) protocols
and does NOT need NetBEUI (Microsoft Raw NetBIOS frame)
protocol.

Samba-2.2 features working NT Domain Control capability and
includes the SWAT (Samba Web Administration Tool) that
allows samba's smb.conf file to be remotely managed using your
favourite web browser. For the time being this is being
enabled on TCP port 901 via xinetd. SWAT is now included in
it's own subpackage, samba-swat.

Users are advised to use Samba-2.2 as a Windows NT4
Domain Controller only on networks that do NOT have a Windows
NT Domain Controller. This release does NOT as yet have
Backup Domain control ability.

Please refer to the WHATSNEW.txt document for fixup information.
This binary release includes encrypted password support.

Please read the smb.conf file and ENCRYPTION.txt in the
docs directory for implementation details.

%if %build_ldap
This package was compiled with LDAP support, which means that 
passwords can ONLY be stored in LDAP, not in smbpasswd files.
To migrate your passwords from smbpasswd into LDAP, try
examples/LDAP/import_smbpasswd.pl using:
/usr/share/samba/scripts/import_smbpasswd.pl </etc/samba/smbpasswd

Scripts for managing users in LDAP have been added to 
/usr/share/samba/scripts, configuration is in /etc/samba/smbldap_conf.pm
%endif

%package client
Summary: Samba (SMB) client programs.
Group: Networking/Other
Requires: samba-common = %{version}
Obsoletes: smbfs

%description client
Samba-client provides some SMB clients, which complement the built-in
SMB filesystem in Linux. These allow the accessing of SMB shares, and
printing to SMB printers.

%if %build_ldap
%package common-ldap
Summary: Files used by both Samba servers and clients with LDAP support
Obsoletes: samba-common
Provides: samba-common
%else
%package common
Summary: Files used by both Samba servers and clients.
Obsoletes: samba-common-ldap
%endif
Group: System/Servers

%if %build_ldap
%description common-ldap
%else
%description common
%endif
Samba-common provides files necessary for both the server and client
packages of Samba.

%package doc
Summary: Documentation for Samba servers and clients.
Group: System/Servers
Requires: samba-common = %{version}

%description doc
Samba-doc provides documentation files for both the server and client
packages of Samba.

%if %build_ldap
%package swat-ldap
Summary: The Samba Web Administration Tool (with LDAP support)
Obsoletes: samba-swat
Provides: samba-swat
Requires: samba-server-ldap = %{version}
%else
%package swat
Summary: The Samba Web Administration Tool.
Obsoletes: samba-swat-ldap
Requires: samba-server = %{version}
%endif
Requires: xinetd
Group: System/Servers
Provides: samba-swat swat

%if %build_ldap
%description swat-ldap
%else
%description swat
%endif
SWAT (the Samba Web Administration Tool) allows the samba smb.conf file
to be remotely managed using your favourite web browser. For the time
being this is being enabled on TCP port 901 via xinetd. Note that
SWAT does not use SSL encryption, nor does it preserve comments in
your smb.conf file. Webmin uses SSL encryption by default, and
preserves comments in configuration files, even if it does not display
them, and is therefore the preferred method for remotely managing
Samba.


%if %build_winbind && %build_ldap
%package winbind-ldap
Requires: samba-common-ldap = %{version}
Obsoletes: samba-winbind
Provides: samba-winbind
%endif
%if %build_winbind && !%build_ldap
%package winbind
Requires: samba-common = %{version}
Obsoletes: samba-winbind-ldap
%endif
%if %build_winbind
Summary: Samba-winbind daemon, utilities and documentation
Group: System/Servers
Provides: winbind samba-winbind
%endif
%if %build_winbind && %build_ldap
%description winbind-ldap
%endif
%if %build_winbind && !%build_ldap
%description winbind
%endif
%if %build_winbind
Provides the winbind daemon and testing tools to allow authentication
and group/user enumeration from a Windows or Samba domain controller.
%endif

%if %build_wins
%package -n nss_wins
Summary: Name Service Switch service for WINS
Group: System/Servers
Requires: samba-common = %{version}
PreReq: glibc
%description -n nss_wins
Provides the libnss_wins shared library which resolves NetBIOS names to
IP addresses.
%endif

#Antivirus packages:
%if %build_fprot
%package vscan-fprot
Summary: On-access virus scanning for samba using FPROT
Group: System/Servers
Requires: samba = %{version}
Provides: samba-vscan
Autoreq: 0
%description vscan-fprot
A vfs-module for samba to implement on-access scanning using the
FPROT antivirus software (which must be installed to use this).
%endif

%if %build_kaspersky
%package vscan-kaspersky
Summary: On-access virus scanning for samba using Kaspersky
Group: System/Servers
Requires: samba = %{version}
Provides: samba-vscan
Autoreq: 0
%description vscan-kaspersky
A vfs-module for samba to implement on-access scanning using the
Kaspersky antivirus software (which must be installed to use this).
%endif

%if %build_mks
%package vscan-mks
Summary: On-access virus scanning for samba using MKS
Group: System/Servers
Requires: samba = %{version}
Provides: samba-vscan
Autoreq: 0
%description vscan-mks
A vfs-module for samba to implement on-access scanning using the
MKS antivirus software (which must be installed to use this).
%endif

%if %build_openantivirus
%package vscan-openantivirus
Summary: On-access virus scanning for samba using OpenAntivirus
Group: System/Servers
Requires: samba = %{version}
Provides: samba-vscan
Autoreq: 0
%description vscan-openantivirus
A vfs-module for samba to implement on-access scanning using the
OpenAntivirus antivirus software (which must be installed to use this).
%endif

%if %build_sophos
%package vscan-sophos
Summary: On-access virus scanning for samba using Sophos
Group: System/Servers
Requires: samba = %{version}
Provides: samba-vscan
Autoreq: 0
%description vscan-sophos
A vfs-module for samba to implement on-access scanning using the
Sophos antivirus software (which must be installed to use this).
%endif

%if %build_symantec
%package vscan-symantec
Summary: On-access virus scanning for samba using Symantec
Group: System/Servers
Requires: samba = %{version}
Provides: samba-vscan
Autoreq: 0
%description vscan-symantec
A vfs-module for samba to implement on-access scanning using the
Symantec antivirus software (which must be installed to use this).
%endif

%if %build_trend
%package vscan-trend
Summary: On-access virus scanning for samba using Trend
Group: System/Servers
Requires: samba = %{version}
Provides: samba-vscan
Autoreq: 0
%description vscan-trend
A vfs-module for samba to implement on-access scanning using the
Trend antivirus software (which must be installed to use this).
%endif

%prep
# Build a summary of how this RPM was built:
%if %build_acl
RPM_EXTRA_OPTIONS="$RPM_EXTRA_OPTIONS --with acl"
%else
RPM_EXTRA_OPTIONS="$RPM_EXTRA_OPTIONS --without acl"
%endif
%if %build_winbind
RPM_EXTRA_OPTIONS="$RPM_EXTRA_OPTIONS --with winbind"
%else
RPM_EXTRA_OPTIONS="$RPM_EXTRA_OPTIONS --without winbind"
%endif
%if %build_wins
RPM_EXTRA_OPTIONS="$RPM_EXTRA_OPTIONS --with wins"
%else
RPM_EXTRA_OPTIONS="$RPM_EXTRA_OPTIONS --without wins"
%endif
%if %build_ldap
RPM_EXTRA_OPTIONS="$RPM_EXTRA_OPTIONS --with ldap"
%else
RPM_EXTRA_OPTIONS="$RPM_EXTRA_OPTIONS --without ldap"
%endif

%if %build_non_default
echo "Building a non-default rpm with the following command-line arguments:"
echo "$RPM_EXTRA_OPTIONS"
echo "This rpm was built with non-default options, thus, to build ">%{SOURCE7}
echo "an identical rpm, you need to supply the following options">>%{SOURCE7}
echo "at build time: $RPM_EXTRA_OPTIONS">>%{SOURCE7}
echo -e "\n%{name}-%{version}-%{release}\n">>%{SOURCE7}
%else
echo "This rpm was built with default options">%{SOURCE7}
echo -e "\n%{name}-%{version}-%{release}\n">>%{SOURCE7}
%endif

%if %build_vscan
%setup -q -a 8 -n %{name}-%{source_ver}
%else
%setup -q -n %{name}-%{source_ver}
%endif
# Current patches
echo "Applying patches for  version: %{ver}"
%patch1 -p1 -b .smbw
%patch2 -p1 -b .gawk
%patch3 -p1 -b .buildroot
%patch4 -p1
%patch5 -p1 -b .gp-reloc-fix
%patch6 -p1
# Version specific patches: current version
%if !%have_pversion
echo "Applying patches for current version: %{ver}"
(cd source/client
%patch101 -p0 -b .lfs
)
( cd source
%patch102 -p0  -b .lfs
)
%patch103 -p1 -b .ldap
%patch104 -p1 -b .mdk
%patch105 -p1
%else
# Version specific patches: upcoming version
echo "Applying patches for new versions: %{pversion}"
%endif

# Limbo patches
%if %have_pversion && %have_pre
echo "Appling patches which should only be applied to prereleases"
%endif

cp %{SOURCE7} .

# Make a copy of examples so that we have a clean one for doc:
cp -a examples examples.bin

%if %build_vscan
# put antivirus files in examples.bin/VFS/
#for av in fprot kaspersky mks openantivirus sophos trend; do
#	[ -e %{vscandir}/$av ] && cp -a %{vscandir}/$av %{vfsdir}
#done
cp -a %{vscandir} %{vfsdir}
#fix stupid directory names:
mv %{vfsdir}/%{vscandir}/openantivirus %{vfsdir}/%{vscandir}/oav
%endif

%build
#%serverbuild
(cd source
autoconf
CPPFLAGS="-I/usr/include/openssl"; export CPPFLAGS
CFLAGS="$RPM_OPT_FLAGS"
%configure      --prefix=%{prefix} \
	--with-fhs \
	--libdir=/etc/samba \
	--sysconfdir=/etc/samba \
	--localstatedir=/var \
	--with-configdir=/etc/samba \
	--with-codepagedir=/var/lib/samba/codepages \
	--with-privatedir=/etc/samba \
	--with-swatdir=%{prefix}/share/swat \
	--with-smbmount \
	--with-syslog \
	--with-automount \
	--with-pam \
	--with-sendfile-support \
	--with-pam_smbpass \
	--with-vfs \
	--with-utmp \
	--with-msdfs \
	--with-smbwrapper \
	--with-libsmbclient \
%if %build_acl
	--with-acl-support	\
%endif
%if %build_ldap
	--with-ldapsam		\
	--with-winbind-ldap-hack \
%endif
	--with-winbind-auth-challenge \
	--with-quotas

#make CFLAGS="$RPM_OPT_FLAGS -D_GNU_SOURCE" all
make CFLAGS="$RPM_OPT_FLAGS -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE" \
	all smbfilter smbwrapper smbcacls pam_smbpass nsswitch nsswitch/libnss_wins.so debug2html
# Build VFS modules (experimental)
cd ../%vfsdir
%configure	--prefix=%{prefix} \
		--mandir=%{prefix}/share/man
make
)

# Build mkntpasswd in examples/LDAP/ for smbldaptools
(
cd examples.bin/LDAP/smbldap-tools/mkntpwd
make
)

# Build antivirus vfs objects:
%if %build_fprot
echo -e "\n\nBuild antivirus VFS modules\n\n"
echo "Building fprot"
(cd %{vfsdir}/%{vscandir}/fprot;make)
%endif
%if %build_kaspersky
echo "Building Kaspersky"
(cd %{vfsdir}/%{vscandir}/kaspersky;make)
%endif
%if %build_mks
echo "Building mks"
(cd %{vfsdir}/%{vscandir}/mks;make)
%endif
%if %build_openantivirus
echo "Building OpenAntivirus"
(cd %{vfsdir}/%{vscandir}/oav;make)
%endif
%if %build_sophos
echo "building sophos"
(cd %{vfsdir}/%{vscandir}/sophos;make)
%endif
%if %build_symantec
echo "Building symantec"
(cd %{vfsdir}/%{vscandir}/symantec;make)
%endif
%if %build_trend
echo "Building Trend"
(cd %{vfsdir}/%{vscandir}/trend;make)
%endif

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/sbin
mkdir -p $RPM_BUILD_ROOT/etc/samba
mkdir -p $RPM_BUILD_ROOT/etc/{logrotate.d,pam.d,xinetd.d}
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
mkdir -p $RPM_BUILD_ROOT/%{prefix}/{bin,sbin}
mkdir -p $RPM_BUILD_ROOT/%{prefix}/share/swat/{images,help,include,using_samba}
mkdir -p $RPM_BUILD_ROOT/%{prefix}/share/swat/using_samba/{figs,gifs}
mkdir -p $RPM_BUILD_ROOT/%{_mandir}/{man1,man5,man7,man8}
mkdir -p $RPM_BUILD_ROOT/var/cache/samba
mkdir -p $RPM_BUILD_ROOT/var/log/samba
mkdir -p $RPM_BUILD_ROOT/var/run/samba
mkdir -p $RPM_BUILD_ROOT/var/spool/samba
mkdir -p $RPM_BUILD_ROOT/var/lib/samba/{netlogon,profiles,printers}
mkdir -p $RPM_BUILD_ROOT/var/lib/samba/printers/{W32X86,WIN40,W32ALPHA,W32MIPS,W32PPC}
mkdir -p $RPM_BUILD_ROOT/var/lib/samba/codepages/src
mkdir -p $RPM_BUILD_ROOT/lib/security
mkdir -p $RPM_BUILD_ROOT%prefix/lib
mkdir -p $RPM_BUILD_ROOT%{_libdir}/samba/vfs
mkdir -p $RPM_BUILD_ROOT%{_datadir}/samba/scripts

# Install standard binary files

for i in nmblookup smbclient smbpasswd smbstatus testparm testprns \
    make_smbcodepage make_unicodemap make_printerdef rpcclient smbspool \
    smbcacls smbclient smbmount smbumount smbsh wbinfo
do
  install -m755 source/bin/$i $RPM_BUILD_ROOT/%{prefix}/bin
done

install -m755 source/bin/smbwrapper.so $RPM_BUILD_ROOT%prefix/lib/smbwrapper.so
install -m755 source/bin/pam_smbpass.so $RPM_BUILD_ROOT/lib/security/pam_smbpass.so
install -m755 source/nsswitch/pam_winbind.so $RPM_BUILD_ROOT/lib/security/pam_winbind.so
install -m755 source/bin/libsmbclient.so $RPM_BUILD_ROOT%prefix/lib/libsmbclient.so

# Install VFS modules
install -m755 %vfsdir/audit.so $RPM_BUILD_ROOT/%{_libdir}/samba/vfs
for i in block recycle
do
 install -m755 %vfsdir/$i/$i.so $RPM_BUILD_ROOT/%{_libdir}/samba/vfs
done

# Antivirus support:
#	mkdir -p $RPM_BUILD_ROOT%{_libdir}/samba/vfs/vscan
	for av in fprot kavp mks oav sophos symantec trend; do
		if [ -d %{vfsdir}/%{vscandir}/$av -a -e %{vfsdir}/%{vscandir}/$av/vscan-$av*.so ];then
			cp %{vfsdir}/%{vscandir}/$av/vscan-$av*.so \
				$RPM_BUILD_ROOT%{_libdir}/samba/vfs/
			cp %{vfsdir}/%{vscandir}/$av/vscan-$av*.conf \
				$RPM_BUILD_ROOT%{_sysconfdir}/%{name}
		fi
	done

for i in mksmbpasswd.sh smbtar convert_smbpasswd
do
  install -m755 source/script/$i $RPM_BUILD_ROOT/%{prefix}/bin
done

# Install secure binary files

for i in smbd nmbd swat smbfilter debug2html smbmnt smbcontrol winbindd
do
  install -m755 source/bin/$i $RPM_BUILD_ROOT/%{prefix}/sbin
done

# Install level 1,5,7,8 man pages

for mpl in 1 5 7 8;do
  mp=$(ls docs/manpages/*.$mpl)
  for i in $mp;do
  install -m644 $i $RPM_BUILD_ROOT/%{_mandir}/man$mpl
  done
done

# Install codepage source files

for i in 437 737 775 850 852 857 861 862 866 932 936 949 950 1125 1251
do
  install -m644 source/codepages/codepage_def.$i $RPM_BUILD_ROOT/var/lib/samba/codepages/src
done

for i in 437 737 775 850 852 857 861 862 866 932 936 949 950 1125 1251 ISO8859-1 ISO8859-2 ISO8859-5 ISO8859-7 ISO8859-8 ISO8859-9 ISO8859-13 ISO8859-15 KOI8-R KOI8-U
do
  install -m644 source/codepages/CP$i.TXT $RPM_BUILD_ROOT/var/lib/samba/codepages/src
done

# Build codepage load files
for i in 437 737 775 850 852 857 861 862 866 932 936 949 950 1125 1251; do
        $RPM_BUILD_ROOT/%{prefix}/bin/make_smbcodepage c $i $RPM_BUILD_ROOT/var/lib/samba/codepages/src/codepage_def.$i $RPM_BUILD_ROOT/var/lib/samba/codepages/codepage.$i
done

# Build unicode load files
for i in 437 737 775 850 852 857 861 862 866 932 936 949 950 1125 1251 ISO8859-1 ISO8859-2 ISO8859-5 ISO8859-7 ISO8859-8 ISO8859-9 ISO8859-13 ISO8859-15 KOI8-R KOI8-U; do
         $RPM_BUILD_ROOT/%{prefix}/bin/make_unicodemap $i $RPM_BUILD_ROOT/var/lib/samba/codepages/src/CP$i.TXT $RPM_BUILD_ROOT/var/lib/samba/codepages/unicode_map.$i
done
rm -rf $RPM_BUILD_ROOT/var/lib/samba/codepages/src

# Install the nsswitch library extension file
for i in wins winbind; do
  install -m755 source/nsswitch/libnss_$i.so $RPM_BUILD_ROOT/lib
done
# Make link for wins and winbind resolvers
( cd $RPM_BUILD_ROOT/lib; ln -s libnss_wins.so libnss_wins.so.2; ln -s libnss_winbind.so libnss_winbind.so.2)

# Install SWAT helper files
        for i in swat/help/*.html docs/htmldocs/*.html; do
                install -m644 $i $RPM_BUILD_ROOT/usr/share/swat/help
        done

        for i in swat/images/*.gif; do
                install -m644 $i $RPM_BUILD_ROOT/usr/share/swat/images
        done

        for i in swat/include/*.html; do
                install -m644 $i $RPM_BUILD_ROOT/usr/share/swat/include
        done

# Install the O'Reilly "Using Samba" book

        for i in docs/htmldocs/using_samba/*.html; do
                install -m644 $i $RPM_BUILD_ROOT/usr/share/swat/using_samba
        done

        for i in docs/htmldocs/using_samba/gifs/*.gif; do
                install -m644 $i $RPM_BUILD_ROOT/usr/share/swat/using_samba/gifs
        done

        for i in docs/htmldocs/using_samba/figs/*.gif; do
                install -m644 $i $RPM_BUILD_ROOT/usr/share/swat/using_samba/figs
        done

# Install other stuff

        install -m644 examples/VFS/recycle/recycle.conf $RPM_BUILD_ROOT/etc/samba/
        install -m644 packaging/Mandrake/smb.conf $RPM_BUILD_ROOT/etc/samba/smb.conf
        install -m644 packaging/Mandrake/smbusers $RPM_BUILD_ROOT/etc/samba/smbusers
        install -m755 packaging/Mandrake/smbprint $RPM_BUILD_ROOT/usr/bin
        install -m755 packaging/Mandrake/findsmb $RPM_BUILD_ROOT/usr/bin
        install -m755 packaging/Mandrake/smb.init $RPM_BUILD_ROOT/etc/rc.d/init.d/smb
        install -m755 packaging/Mandrake/smb.init $RPM_BUILD_ROOT/usr/sbin/samba
	install -m755 packaging/Mandrake/winbind.init $RPM_BUILD_ROOT/etc/rc.d/init.d/winbind
	install -m755 packaging/Mandrake/winbind.init $RPM_BUILD_ROOT/usr/sbin/winbind
        install -m644 packaging/Mandrake/samba.pamd $RPM_BUILD_ROOT/etc/pam.d/samba
	install -m644 packaging/Mandrake/system-auth-winbind.pamd $RPM_BUILD_ROOT/etc/pam.d/system-auth-winbind
#
        install -m644 $RPM_SOURCE_DIR/samba.log $RPM_BUILD_ROOT/etc/logrotate.d/samba
	install -m644 packaging/Mandrake/samba-slapd-include.conf $RPM_BUILD_ROOT%{_sysconfdir}/samba/samba-slapd.include

# Install smbldap-tools scripts:
for i in examples/LDAP/smbldap-tools/*.pl; do
	install -m 750 $i $RPM_BUILD_ROOT/%{_datadir}/samba/scripts/
	ln -s %{_datadir}/%{name}/scripts/`basename $i` $RPM_BUILD_ROOT/%{_bindir}/`basename $i|sed -e 's/\.pl//g'`
done

install -m 750 examples/LDAP/smbldap-tools/smbldap_tools.pm $RPM_BUILD_ROOT/%{_datadir}/samba/scripts/

# The conf file	
install -m 640 examples/LDAP/smbldap-tools/smbldap_conf.pm $RPM_BUILD_ROOT/%{_sysconfdir}/%{name}

# Link both smbldap*.pm into vendor-perl (any better ideas?)
mkdir -p %{buildroot}/%{perl_vendorlib}
ln -s %{_sysconfdir}/samba/smbldap_conf.pm $RPM_BUILD_ROOT/%{perl_vendorlib}
ln -s %{_datadir}/samba/scripts/smbldap_tools.pm $RPM_BUILD_ROOT/%{perl_vendorlib}

#mkntpwd
install -m750 examples.bin/LDAP/smbldap-tools/mkntpwd/mkntpwd %{buildroot}/%{_sbindir}

# Samba smbpasswd migration script:
install -m700 examples/LDAP/export_smbpasswd.pl $RPM_BUILD_ROOT/%{_datadir}/samba/scripts/
install -m700 examples/LDAP/import_smbpasswd.pl $RPM_BUILD_ROOT/%{_datadir}/samba/scripts/



# make a conf file for winbind from the default one:
	cat packaging/Mandrake/smb.conf|sed -e  's/^;  winbind/  winbind/g;s/^;  obey pam/  obey pam/g; s/^;   printer admin = @"D/   printer admin = @"D/g;s/^;   password server = \*/   password server = \*/g;s/^;  template/  template/g; s/^   security = user/   security = domain/g' > packaging/Mandrake/smb-winbind.conf
        install -m644 packaging/Mandrake/smb-winbind.conf $RPM_BUILD_ROOT/etc/samba/smb-winbind.conf

# Link smbmount to /sbin/mount.smb and /sbin/mount.smbfs

        ln -s /%{prefix}/bin/smbmount $RPM_BUILD_ROOT/sbin/mount.smb
        ln -s /%{prefix}/bin/smbmount $RPM_BUILD_ROOT/sbin/mount.smbfs
        echo 127.0.0.1 localhost > $RPM_BUILD_ROOT/etc/samba/lmhosts

# Link smbspool to CUPS (does not require installed CUPS)

        mkdir -p $RPM_BUILD_ROOT/usr/lib/cups/backend
        ln -s /usr/bin/smbspool $RPM_BUILD_ROOT/usr/lib/cups/backend/smb

# xinetd support

        mkdir -p $RPM_BUILD_ROOT/etc/xinetd.d
        install -m644 %{SOURCE3} $RPM_BUILD_ROOT/etc/xinetd.d/swat

# menu support

mkdir -p $RPM_BUILD_ROOT%{_menudir}
cat > $RPM_BUILD_ROOT%{_menudir}/%{name} << EOF
?package(%{name}):command="gnome-moz-remote http://localhost:901/" needs="gnome" \
icon="swat.xpm" section="Configuration/Networking" title="Samba Configuration" \
longtitle="The Swat Samba Administration Tool"
?package(%{name}):command="sh -c '\$BROWSER http://localhost:901/'" needs="x11" \
icon="swat.xpm" section="Configuration/Networking" title="Samba Configuration" \
longtitle="The Swat Samba Administration Tool"
EOF

mkdir -p $RPM_BUILD_ROOT%{_liconsdir} $RPM_BUILD_ROOT%{_iconsdir} $RPM_BUILD_ROOT%{_miconsdir}

bzcat %{SOURCE4} > $RPM_BUILD_ROOT%{_liconsdir}/swat.xpm
bzcat %{SOURCE5} > $RPM_BUILD_ROOT%{_iconsdir}/swat.xpm
bzcat %{SOURCE6} > $RPM_BUILD_ROOT%{_miconsdir}/swat.xpm

bzcat %{SOURCE10}> $RPM_BUILD_ROOT%{_datadir}/samba/scripts/print-pdf

# Delete files which will not be included, so that /usr/lib/rpm/check-files
# doesn't error out when Checking for unpackaged file(s)
%if ! %build_ldap
%endif

%if ! %build_acl
%endif

%if ! %build_winbind
rm -f $RPM_BUILD_ROOT%{_sbindir}/winbind
rm -f $RPM_BUILD_ROOT%{_sbindir}/winbindd
rm -f $RPM_BUILD_ROOT%{_bindir}/wbinfo
rm -f $RPM_BUILD_ROOT/lib/security/pam_winbind*
rm -f $RPM_BUILD_ROOT/lib/libnss_winbind*
rm -f $RPM_BUILD_ROOT/etc/rc.d/init.d/winbind
rm -f $RPM_BUILD_ROOT/etc/pam.d/system-auth-winbind
rm -f $RPM_BUILD_ROOT%{_mandir}/man8/winbindd.8*
rm -f $RPM_BUILD_ROOT%{_mandir}/man1/wbinfo.1*
%endif

%if ! %build_wins
rm -f $RPM_BUILD_ROOT/lib/libnss_wins.so*
%endif

%ifarch alpha
rm -f $RPM_BUILD_ROOT/sbin/mount.smb
rm -f $RPM_BUILD_ROOT/sbin/mount.smbfs
rm -f $RPM_BUILD_ROOT%{_bindir}/smbmount
rm -f $RPM_BUILD_ROOT%{_bindir}/smbumount
rm -f $RPM_BUILD_ROOT%{_sbindir}/smbmnt
rm -f $RPM_BUILD_ROOT%{_mandir}/man8/smbmnt.8*
rm -f $RPM_BUILD_ROOT%{_mandir}/man8/smbmount.8*
rm -f $RPM_BUILD_ROOT%{_mandir}/man8/smbumount.8*
%endif

#Files for antivirus support:
%if ! %build_fprot
rm -f $RPM_BUILD_ROOT%{_libdir}/samba/vfs/vscan-fprotd.so
%endif

%if ! %build_kaspersky
rm -f $RPM_BUILD_ROOT%{_libdir}/samba/vfs/vscan-kavp.so
%endif

%if ! %build_mks
rm -f $RPM_BUILD_ROOT%{_libdir}/samba/vfs/vscan-mksd.so
%endif

%if ! %build_openantivirus
rm -f $RPM_BUILD_ROOT%{_libdir}/samba/vfs/vscan-oav.so
%endif

%if ! %build_sophos
rm -f $RPM_BUILD_ROOT%{_libdir}/samba/vfs/vscan-sophos.so
%endif

%if ! %build_symantec
rm -f $RPM_BUILD_ROOT%{_libdir}/samba/vfs/vscan-symantec.so
%endif

%if ! %build_trend
rm -f $RPM_BUILD_ROOT%{_libdir}/samba/vfs/vscan-trend.so
%endif

%clean
rm -rf $RPM_BUILD_ROOT

%if %build_ldap
%post -n samba-server-ldap
%else
%post -n samba-server
%endif
%_post_service smb
#/sbin/chkconfig --level 35 smb on

# Add a unix group for samba machine accounts
groupadd -frg 421 machines

%if %build_ldap
%post -n samba-common-ldap
%else
%post -n samba-common
%endif
# Basic migration script for pre-2.2.1 users,
# since smb config moved from /etc to /etc/samba

mkdir -p /etc/samba
for s in smb.conf smbusers smbpasswd printers.def secrets.tdb lmhosts; do
[ -f /etc/$s ] && {
        cp -f /etc/$s /etc/$s.OLD
        mv -f /etc/$s /etc/samba/
}
done

# Migrate tdb's from /var/lock/samba (taken from official samba spec file):
for i in /var/lock/samba/*.tdb
do
if [ -f $i ]; then
	newname=`echo $i | sed -e's|var\/lock\/samba|var\/cache\/samba|'`
	echo "Moving $i to $newname"
	mv $i $newname
fi
done

# Remove the transient tdb files (modified from version in off. samba spec:
for TDB in brlock unexpected locking messages; do
        if [ -e /var/cache/samba/$TDB.tdb ]; then
                rm -f /var/cache/samba/$TDB.tdb;
        fi;
done

if [ -d /var/lock/samba ]; then
        rm -rf /var/lock/samba
fi
# Make a symlink on /usr/lib/smbwrapper.so in /usr/bin
# to fix smbsh problem (another way to do that, anyone???)

ln -sf /usr/lib/smbwrapper.so /usr/bin/smbwrapper.so

# Let's create a proper /etc/samba/smbpasswd file
[ -f /etc/samba/smbpasswd ] || {
	echo "Creating password file for samba..."
	touch /etc/samba/smbpasswd
}

# And this too, in case we don't have smbd to create it for us
[ -f /var/cache/samba/unexpected.tdb ] || {
	touch /var/cache/samba/unexpected.tdb
}

# Let's define the proper paths for config files
perl -pi -e 's/(\/etc\/)(smb)/\1samba\/\2/' /etc/samba/smb.conf

# Fix the logrotate.d file from smb and nmb to smbd and nmbd
if [ -f /etc/logrotate.d/samba ]; then
        perl -pi -e 's/smb /smbd /' /etc/logrotate.d/samba
        perl -pi -e 's/nmb /nmbd /' /etc/logrotate.d/samba
fi

# And not loose our machine account SID
[ -f /etc/MACHINE.SID ] && mv -f /etc/MACHINE.SID /etc/samba/ ||:

%if %build_winbind && %build_ldap
%post -n samba-winbind-ldap
%endif
%if %build_winbind && !%build_ldap
%post -n samba-winbind
%endif
%if %build_winbind
%_post_service winbind
if [ $1 = 1 ]; then
#    /sbin/chkconfig winbind on
    cp -af /etc/nsswitch.conf /etc/nsswitch.conf.rpmsave
    cp -af /etc/nsswitch.conf /etc/nsswitch.conf.rpmtemp
    for i in passwd group;do
        grep ^$i /etc/nsswitch.conf |grep -v 'winbind' 1>/dev/null 2>/dev/null
        if [ $? = 0 ];then
            echo "Adding a winbind entry to the $i section of /etc/nsswitch.conf"
            awk '/^'$i'/ {print $0 " winbind"};!/^'$i'/ {print}' /etc/nsswitch.conf.rpmtemp >/etc/nsswitch.conf;
	    cp -af /etc/nsswitch.conf /etc/nsswitch.conf.rpmtemp
        else
            echo "$i entry found in /etc/nsswitch.conf"
        fi
    done
    if [ -f /etc/nsswitch.conf.rpmtemp ];then 
        rm -f /etc/nsswitch.conf.rpmtemp;fi
fi
%endif

%if %build_winbind && %build_ldap
%preun -n samba-winbind-ldap
%endif
%if %build_winbind && !%build_ldap
%preun -n samba-winbind
%endif
%if %build_winbind
%_preun_service winbind
if [ $1 = 0 ]; then
	echo "Removing winbind entries from /etc/nsswitch.conf"
	perl -pi -e 's/ winbind//' /etc/nsswitch.conf

#	/sbin/chkconfig winbind reset
fi
%endif

%if %build_wins
%post -n nss_wins
if [ $1 = 1 ]; then
    cp -af /etc/nsswitch.conf /etc/nsswitch.conf.rpmsave
    grep '^hosts' /etc/nsswitch.conf |grep -v 'wins' >/dev/null
    if [ $? = 0 ];then
        echo "Adding a wins entry to the hosts section of /etc/nsswitch.conf"
        awk '/^hosts/ {print $0 " wins"};!/^hosts/ {print}' /etc/nsswitch.conf.rpmsave >/etc/nsswitch.conf;
    else
        echo "wins entry found in /etc/nsswitch.conf"
    fi
#    else
#        echo "Upgrade, leaving nsswitch.conf intact"
fi

%preun -n nss_wins
if [ $1 = 0 ]; then
	echo "Removing wins entry from /etc/nsswitch.conf"
	perl -pi -e 's/ wins//' /etc/nsswitch.conf
#else
#	echo "Leaving /etc/nsswitch.conf intact"
fi
%endif %build_wins

%if %build_ldap
%preun -n samba-server-ldap
%else
%preun -n samba-server
%endif

if [ $1 = 0 ] ; then
%_preun_service smb
    if [ -d /var/log/samba ]; then
      rm -rf /var/log/samba/*
    fi
    if [ -d /var/cache/samba ]; then
      mv -f /var/cache/samba /var/cache/samba.BAK
    fi
fi

%if %build_ldap
%preun -n samba-common-ldap
%else
%preun -n samba-common
%endif

if [ $1 = 0 ] ; then
    for n in /etc/samba/codepages/*; do
        if [ "$n" != "/etc/samba/codepages/src" ]; then
            rm -rf $n
        fi
    done
fi


%if %build_ldap
%post -n samba-swat-ldap
%else
%post -n samba-swat
%endif
# Change only_from entry in /etc/xinetd.d/swat (localhost bug)
[[ `/bin/grep "localhost" /etc/xinetd.d/swat` ]] && {
echo "-- Setting swat xinetd only_from entry to 127.0.0.1"
perl -pi -e 's/localhost/127.0.0.1/' /etc/xinetd.d/swat
}
if [ -f /var/lock/subsys/xinetd ]; then
        service xinetd reload >/dev/null 2>&1 || :
fi
%update_menus

%if %build_ldap
%postun -n samba-swat-ldap
%else
%postun -n samba-swat
%endif
# Remove swat entry from xinetd
if [ -f /var/lock/subsys/xinetd ]; then
	service xinetd reload &>/dev/null || :
fi
%clean_menus

%triggerpostun -- samba < 1.9.18p7

if [ $1 != 0 ]; then
    /sbin/chkconfig --level 35 smb on
fi

%triggerpostun -- samba < 2.0.5a-3, samba >= 2.0.0

if [ $1 != 0 ]; then
        [ ! -d /var/lock/samba ] && mkdir -m 0755 /var/lock/samba ||:
        [ ! -d /var/spool/samba ] && mkdir -m 1777 /var/spool/samba ||:
        [ -f /etc/inetd.conf ] && chmod 644 /etc/services /etc/inetd.conf ||:
fi

%if %build_ldap
%files server-ldap
%else
%files server
%endif
%defattr(-,root,root)
#%attr(-,root,root) %{prefix}/sbin/*
%attr(-,root,root) /sbin/*
#%attr(-,root,root) %{prefix}/bin/*
#%attr(755,root,root) /lib/*
%{_sbindir}/samba
%{_sbindir}/smbd
%{_sbindir}/nmbd
%{_sbindir}/smbcontrol
%{_sbindir}/mkntpwd
#%{prefix}/bin/addtosmbpass
%{_bindir}/mksmbpasswd.sh
%{_bindir}/smbstatus
%{_bindir}/convert_smbpasswd
%attr(755,root,root) /lib/security/pam_smbpass*
%attr(-,root,root) %config(noreplace) /etc/samba/smbusers
%attr(-,root,root) %config /etc/rc.d/init.d/smb
%attr(-,root,root) %config(noreplace) /etc/logrotate.d/samba
%attr(-,root,root) %config(noreplace) /etc/pam.d/samba
%attr(-,root,root) %config(noreplace) /etc/samba/samba-slapd.include
%{_mandir}/man1/smbstatus.1*
%{_mandir}/man5/smbpasswd.5*
%{_mandir}/man7/samba.7*
%{_mandir}/man8/smbd.8*
%{_mandir}/man8/nmbd.8*
%{_mandir}/man1/smbcontrol.1*
#%{_mandir}/man1/lmhosts.1*
%attr(755,root,root) %dir /var/lib/samba/netlogon
%attr(775,root,users) %dir /var/lib/samba/profiles
%attr(775,root,adm) %dir /var/lib/samba/printers/*
%attr(755,root,root) %dir %{_libdir}/samba/vfs
%attr(755,root,root) %{_libdir}/samba/vfs/audit.so
%attr(755,root,root) %{_libdir}/samba/vfs/block.so
%attr(755,root,root) %{_libdir}/samba/vfs/recycle.so
%attr(-,root,root) %config(noreplace) %{_sysconfdir}/samba/recycle.conf
#%attr(775,root,root) %dir %{_libdir}/samba/vfs/vscan
%attr(1777,root,root) %dir /var/spool/samba
%dir %{_datadir}/%{name}/scripts
%attr(0755,root,root) %{_datadir}/%{name}/scripts/print-pdf
%attr(0750,root,adm) %{_datadir}/%{name}/scripts/smbldap*.pl
%attr(0750,root,adm) %{_bindir}/smbldap*
%attr(0640,root,adm) %config(noreplace) %{_sysconfdir}/%{name}/smbldap_conf.pm
%attr(0644,root,root) %{_datadir}/%{name}/scripts/smbldap_tools.pm
%{perl_vendorlib}/*.pm
%attr(0700,root,root) %{_datadir}/%{name}/scripts/*port_smbpasswd.pl


%files doc
%defattr(644,root,root,755)
%doc README COPYING Manifest Read-Manifest-Now
%doc WHATSNEW.txt Roadmap
%doc README.%{name}-mandrake-rpm
%doc docs
%doc examples
%doc swat/README
%attr(-,root,root) %{prefix}/share/swat/using_samba/*

%if %build_ldap
%files swat-ldap
%else
%files swat
%endif
%defattr(-,root,root)
%config(noreplace) /etc/xinetd.d/swat
%attr(-,root,root) /sbin/*
%{_sbindir}/swat
%{_menudir}/%{name}
%{_miconsdir}/*.xpm
%{_liconsdir}/*.xpm
%{_iconsdir}/*.xpm
%attr(-,root,root) %{_datadir}/swat/help/*
%attr(-,root,root) %{_datadir}/swat/images/*
%attr(-,root,root) %{_datadir}/swat/include/*
%{_mandir}/man8/swat.8*

%files client
%defattr(-,root,root)
%ifnarch alpha
/sbin/mount.smb
/sbin/mount.smbfs
%attr(755,root,root) %{_bindir}/smbmount
%attr(4755,root,root) %{_bindir}/smbumount
%attr(4755,root,root) %{_sbindir}/smbmnt
%{_mandir}/man8/smbmnt.8*
%{_mandir}/man8/smbmount.8*
%{_mandir}/man8/smbumount.8*
%endif
%{_bindir}/nmblookup
%{_bindir}/findsmb
%{_bindir}/smbclient
%{_bindir}/smbprint
%{_bindir}/smbtar
%{_bindir}/smbspool
# Link of smbspool to CUPS
%{_libdir}/cups/backend/smb
%{_mandir}/man1/nmblookup.1*
%{_mandir}/man1/findsmb.1*
%{_mandir}/man1/smbclient.1*
%{_mandir}/man1/smbtar.1*
%{_mandir}/man8/smbspool.8*

%if %build_ldap
%files common-ldap
%else
%files common
%endif
%defattr(-,root,root)
%dir /var/cache/samba
%dir /var/log/samba
%dir /var/run/samba
%{_bindir}/make_smbcodepage
%{_bindir}/make_unicodemap
%{_bindir}/testparm
%{_bindir}/testprns
%{_bindir}/make_printerdef
%{_bindir}/rpcclient
%{_bindir}/smbsh
%{_bindir}/smbpasswd
%{_bindir}/smbcacls
%{_sbindir}/debug2html
%{_sbindir}/smbfilter
%{_libdir}/smbwrapper.so
%{_libdir}/libsmbclient.so
%attr(-,root,root) %config(noreplace) /etc/samba/smb.conf
%attr(-,root,root) %config(noreplace) /etc/samba/smb-winbind.conf
%attr(-,root,root) %config(noreplace) /etc/samba/lmhosts
%attr(-,root,root) /var/lib/samba/codepages
%{_mandir}/man1/make_smbcodepage.1*
%{_mandir}/man1/make_unicodemap.1*
%{_mandir}/man1/testparm.1*
%{_mandir}/man1/smbsh.1*
%{_mandir}/man1/testprns.1*
%{_mandir}/man5/smb.conf.5*
%{_mandir}/man5/lmhosts.5*
%{_mandir}/man8/smbpasswd.8*
%{_mandir}/man1/smbcacls.1*
%{_mandir}/man1/rpcclient.1*
%{_mandir}/man8/pdbedit.8*

#%if %build_winbind
#%if %build_ldap
%if %build_winbind && %build_ldap
%files winbind-ldap
%endif
#%else
%if %build_winbind && !%build_ldap
%files winbind
%endif
%if %build_winbind
%defattr(-,root,root)
%{_sbindir}/winbindd
%{_sbindir}/winbind
%{_bindir}/wbinfo
%attr(755,root,root) /lib/security/pam_winbind*
%attr(755,root,root) /lib/libnss_winbind*
%attr(-,root,root) %config /etc/rc.d/init.d/winbind
%attr(-,root,root) %config(noreplace) /etc/pam.d/system-auth-winbind
%{_mandir}/man8/winbindd.8*
%{_mandir}/man1/wbinfo.1*
%endif

%if %build_wins
%files -n nss_wins
%defattr(-,root,root)
%attr(755,root,root) /lib/libnss_wins.so*
%endif

#Files for antivirus support:
%if %build_fprot
%files vscan-fprot
%defattr(-,root,root)
%{_libdir}/samba/vfs/vscan-fprotd.so
%config(noreplace) %{_sysconfdir}/%{name}/vscan-fprotd.conf
%doc %{vfsdir}/%{vscandir}/INSTALL
%endif

%if %build_kaspersky
%files vscan-kaspersky
%defattr(-,root,root)
%{_libdir}/samba/vfs/vscan-kavp.so
%config(noreplace) %{_sysconfdir}/%{name}/vscan-kavp.conf
%doc %{vfsdir}/%{vscandir}/examples.bin/VFS/kaspersky/INSTALL
%endif

%if %build_mks
%files vscan-mks
%defattr(-,root,root)
%{_libdir}/samba/vfs/vscan-mksd.so
%config(noreplace) %{_sysconfdir}/%{name}/vscan-mks*.conf
%doc %{vfsdir}/%{vscandir}/INSTALL
%endif

%if %build_openantivirus
%files vscan-openantivirus
%defattr(-,root,root)
%{_libdir}/samba/vfs/vscan-oav.so
%config(noreplace) %{_sysconfdir}/%{name}/vscan-oav.conf
%doc %{vfsdir}/%{vscandir}/INSTALL
%endif

%if %build_sophos
%files vscan-sophos
%defattr(-,root,root)
%{_libdir}/samba/vfs/vscan-sophos.so
%config(noreplace) %{_sysconfdir}/%{name}/vscan-sophos.conf
%doc  %{vfsdir}/%{vscandir}/INSTALL
%endif

%if %build_symantec
%files vscan-symantec
%defattr(-,root,root)
%{_libdir}/samba/vfs/vscan-symantec.so
%config(noreplace) %{_sysconfdir}/%{name}/vscan-symantec.conf
%doc %{vfsdir}/%{vscandir}/INSTALL
%endif

%if %build_trend
%files vscan-trend
%defattr(-,root,root)
%{_libdir}/samba/vfs/vscan-trend.so
%config(noreplace) %{_sysconfdir}/%{name}/vscan-trend.conf
%doc %{vfsdir}/%{vscandir}/INSTALL
%endif

%changelog
* Fri Feb 14 2003 Buchan Milne <bgmilne@linux-mandrake.com> 2.2.7a-4mdk
- Fix build openantivirus with default scanners
- buildrequire popt-devel
- From Jim Collings <jcllings@tsunamicomm.net>
   - Patched smbldap-tools and created links to same in /usr/bin

* Thu Jan 23 2003 Buchan Milne <bgmilne@linux-mandrake.com> 2.2.7a-3mdk
- Two patches to fix large file support (smbtar:p101 and smbclient:p102)
- Patch to enable ldap referral (103)
- Build all vscan except kav (requires kaspersky lib) with --with-scanners
- Allow adm group to install printer drivers and use smbldaptools by default
- Remove smb.conf man page conflict

* Thu Jan 02 2003 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.7a-2mdk
- Rebuilt because of new rpm macros and new glibc.
- Happy new year 2003 to all samba developers, contributors and users!

* Wed Dec 11 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.7a-1mdk
- Upgraded to 2.2.7a.

* Sun Dec 08 2002 Buchan Milne <bgmilne@linux-mandrake.com> 2.2.7-5mdk
- samba-vscan 0.3.1 (and make it build again)
- Make all vscan packages provide samba-vscan
- All scanner packages (besides kaspersky) can be built without the 
  scanner installed, but we don't quite to this yet ...
- Add vscan-(scanner).conf files
- Add winbind-auth-challenge to configure, for squid support
- Use winbind-ldap-hack only when building with ldapsam support
  since no-one has been able to test this thoroughly, and my only
  tests indicated performance problems with it (and I need this RPM to
  work for squid)

* Tue Nov 26 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.7-4mdk
- Fix perms on doc.
- Cleaned up specfile a bit.
- Added support for upcoming Mandrake Linux 9.1 in auto build process.

* Tue Nov 26 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.7-3mdk
- Put (noreplace) back in %files swat.
- Changed only_from entry in sample swat to "127.0.0.1".
- Change only_from entry in /etc/xinetd.d/swat to "127.0.0.1" on %post swat.

* Fri Nov 22 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.7-2mdk
- Removed noreplace of /etc/xinetd.d/swat on update.
- Updated samba-vscan (0.3.0).

* Wed Nov 20 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.7-1mdk
- Update to 2.2.7.
- Removed patch 38.

* Sat Nov 16 2002 Alexander Skwar <ASkwar@DigitalProjects.com> 2.2.6-6mdk
- Remove installed files which will not be included due to build options,
  so that /usr/lib/rpm/check-files doesn't error out when
  Checking for unpackaged file(s)
- Add debug2html, smbfilter to common package
- Add /usr/sbin/winbind to winbind package
- Add rpcclient manpage to common package
- Add smbspool, pdbedit manpage to client package

* Wed Nov 06 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.6-5mdk
- add winbind ldap hack again, with proper build-require (libldap2-devel)
- enable --with-sendfile-support (default in 3.0. Increases performance).

* Wed Oct 30 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.6-4mdk
- Patch to fix fd leak with kernel change notify. (38) (--Jeremy Allison)

* Fri Oct 25 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.6-3mdk
- Add URL to http://www.samba.org
- Add --with-winbind-ldap-hack to remove the need to enable 
  pre-windows2000-compatible access for winbind.

* Tue Oct 22 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.6-2mdk
- Really switch back to std versioning.
- samba-vscan v-0.2.5e

* Fri Oct 18 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.6-1.3mdk
- Clean-up patches.
- Switch back to normal versioning.
- added ISO8859-8 (Hebrew).

* Fri Oct 18 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.6-1.2mdk
- Birthday release ;o)
- Added smbumount patch back (37).

* Thu Oct 17 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.6-1.1mdk
- New version: 2.2.6

* Wed Oct 16 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.5-23mdk
- Upgrade to 2.2.6rc4
- 2.2.6-1.0.rc4.1mdk
- remove patch 36.

* Mon Oct 14 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.5-22mdk
- Upgrade to 2.2.6rc3
- 2.2.6-1.0.rc3.1mdk

* Thu Oct 10 2002 Buchan Milne <bgmilne@linux-mandrake.com> 2.2.5-21mdk
- Put docs back (aka rpm sucks, builds cleanly when doc fails)
- 2.2.6-1.0.rc2.3mdk

* Thu Oct 10 2002 Buchan Milne <bgmilne@linux-mandrake.com> 2.2.5-20mdk
- Fix typo in print-pdf script
- Make spec resistant to arbitrary pre/alpha/rc/beta/iamnotfinishedyet strings
  in version
- Stop filling CVS with READMEs (use README.samba-mandrake-rpm instead)  
- Make example profiles share writeable by default, and add auto-creation
  example (smb.conf)
- Make ps printing example remove printed files by default (smb.conf)
- Fix ntlogon example (smb.conf)

* Thu Oct 10 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.5-19mdk
- almost 2.26 (rc2)!

* Mon Oct 07 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.5-18mdk
- add lazy umount patch for smbumount to allow smbumount to handle
  broken connection. (36) (-- <kevin@vega.idv.tw>)

* Thu Sep 05 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.5-17mdk
- changed localhost entry in /etc/xinetd.d/swat to 127.0.0.1
  for resolving issue.

* Thu Aug 15 2002 Buchan Milne <bgmilne@linux-mandrake.com> 2.2.5-16mdk
- Don't remove swat xinetd config (that's what RPM is for!)
- Don't clean menus twice
- This should also be 2.2.6-1.1mdk (build from official samba tarball)
- Use samba-slapd-include.conf from packaging dir (patch it in for 2.2.5)

* Wed Aug 07 2002 Buchan Milne <bgmilne@linux-mandrake.com> 2.2.5-15mdk
- put /var/log/samba and /var/run/samba in common (for winbind - sbenedict)
- Integrate smbldap-tools, now in /usr/share/scripts/samba, with examples
  in smb.conf, configuration is /etc/samba/smbldap_conf.pm (please test!)
  This links smbldap_tools.pm and smbldap_conf.pm into perl_vendorlib 
  (better ideas?)
- Add mkntpwd (for smbldap-tools)
- Samba smbpasswd->ldap migration script also in samba scripts dir.
- Add recycle.conf, fix recycle example in smb.conf (pascal@vmfacility.fr)
- spec cleanups
- bump samba-vscan to 0.2.5c (not tested though - yet).

* Wed Jul 24 2002 Buchan Milne <bgmilne@linux-mandrake.com> 2.2.5-14mdk
- Fix ldap description (really only when built with LDAP)
- Expand -server description
- more winbind examples in smb.conf
- add winbind version of default smb.conf (smb-winbind.conf)
- Add PDF-creation script and share
- Rebuild for new acl

* Wed Jul 24 2002 Thierry Vignaud <tvignaud@mandrakesoft.com> 2.2.5-13mdk
- rebuild for new readline

* Mon Jul 22 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.5-12mdk
- fixed source no. for samba-slapd.include (-- Oden Eriksson)
- added CVS win2k copy bug patch (34) (-- Jeremy Alison)

* Tue Jul 16 2002 Buchan Milne <bgmilne@linux-mandrake.com> 2.2.5-11mdk
- Fix winbind init script (doesn't need nmbd)
- Add ldap examples, pam password change, obey pam restrictions (winbind)
  in smb.conf (disabled of course)
- Add sample LDAP configuration (/etc/samba/samba-slapd.include
- Add password section to /etc/pam.d/samba (pam password change)
- buildrequires readline-devel
- Ensure unexpected.tdb exists for winbind/client without smbd (post in common)

* Wed Jul 10 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.5-10mdk
- patch (30) to randomize the way smb re-reads config files (-- Jonathan Knight)

* Thu Jul 04 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.5-9mdk
- changed a few perms from 775 to 755 to make rpmlint happy.

* Mon Jul 01 2002 Geoffrey Lee <snailtalk@mandrakesoft.com> 2.2.5-8mdk
- Don't make smbmnt and smbumount group writable.

* Mon Jul 01 2002 Geoffrey Lee <snailtalk@mandrakesoft.com> 2.2.5-7mdk
- Really fix the Alpha (I suck).

* Thu Jun 27 2002  Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.5-6mdk
- directory listings vs NT/win2k servers helper patch (30) (--Urban Widmark)
- build --with-libsmbclient

* Thu Jun 27 2002  Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.5-5mdk
- parsing fix for spoolss (29) (-- Jerry Carter)
- Don't make the -ldap packages conflicts with the "normal" packages,
  but make them Obsoletes (-- Alexander Skwar)

* Thu Jun 27 2002 Geoffrey Lee <snailtalk@mandrakesoft.com> 2.2.5-4mdk
- Alpha build fix.

* Wed Jun 26 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.5-3mdk
- ldap patch (28) (-- Jerry Carter)

* Wed Jun 19 2002 Buchan Milne <bgmilne@linux-mandrake.com> 2.2.5-2mdk
- Fix build on 8.1 (no nested conditionals)
- Make provision for newer Mandrake releases

* Wed Jun 19 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.5-1mdk
- 2.2.5 is out!
- removed patch27 (included in new release)

* Mon Jun 18 2002 Buchan Milne <bgmilne@linux-mandrake.com> 2.2.5-0.pre1.5mdk
- Modifications for samba-2.2.5 source release
- New samba-vscan (0.2.5a)
- Samba releases will be 1.prelease.mdk (to upgrade prereleases nicely).

* Mon Jun 17 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.5-0.pre1.4mdk
- docs are now 755.
- Please TEST, REBUILD with or without LDAP etc., and report any errors... Thanks!

* Mon Jun 17 2002 Buchan Milne <bgmilne@linux-mandrake.com> 2.2.5-0.pre1.3mdk
- s/%%define/%%global for macros used for package definitions (so --with
  ldap and --with sophos actually build appropriate packages f.e.)
- Obsoletes: samba in samba-server
- Prevent vscan vfs objects going into samba-server (!deps on scanner)
- Disable automatic dependency checks for vscan subpackages
- Build vfs objects in a copy of examples (examples.bin) so no bins in doc
- Make vi faster ;-) (remove spurious single quote in swat description)
- Add doc (INSTALL) for vscan packages
- Try and sort out dependencies and conflicts

* Fri Jun 14 2002 Buchan Milne <bgmilne@linux-mandrake.com> 2.2.5-0.pre1.2mdk
- Patch27 (prevent all samba binaries linking to libldap)
- New samba-swat-ldap and samba-winbind-ldap packages
- move smbcacls to samba-common(-ldap), since it links to libldap
- Only packages which don't build ldap-specific are nss_wins,doc and client

* Mon Jun 10 2002 Buchan Milne <bgmilne@linux-mandrake.com> 2.2.5-0.pre1.1mdk
- Introduce new samba-server-ldap and samba-common-ldap packages

* Mon Jun 10 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.5-0.pre1.0mdk
- first release with 2.2.5pre1.
- samba-*.rpm now renamed samba-server-*.rpm
- vfs modules are back in town

* Tue Jun 04 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.4-5mdk
- changed vfs location in sample mdk smb.conf.

* Mon Jun 03 2002 Buchan Milne <bgmilne@linux-mandrake.com> 2.2.4-4mdk
- More patch cleaning
- Antivirus support (optional at build time). Please test if you have one of 
  fprot, kaspersky,mks,symantec or trend. Sophos has been tested and builds
  and works.
- Move all vfs objects to /usr/lib/samba/vfs

* Mon May 27 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.4-3mdk
- Rollup patch for most of the printing fixes in SAMBA_2_2. (-- Jerry Carter)
- build + install VFS objects
- patched VFS network recycle_bin (-- Kohei Yoshida)
- added VFS examples in smb.conf

* Mon May 13 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.4-2mdk
- Cleaned a few useless patches.
- Added a few codepages.
- LDAP support in option.

* Fri May 03 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.4-1mdk
- Upped to 2.2.4.
- Default build for cooker now includes LDAP support (as in 2.2.X).
- Commented pversion/prelease defs.
- Modif of the Cooker detection routine (use of grep).

* Fri Apr 26 2002 Buchan Milne <bgmilne@cae.co.za> 2.2.3a-12mdk
- Final changes for 2.2.4 release
- Removed patches 4(nsl),11(smbspool-guest)
- Made patch 7 (2.2.3a-init) release specific

* Sun Apr 21 2002 Buchan Milne <bgmilne@cae.co.za> 2.2.3a-11mdk
- Tested with CVS snapshot (upcoming relaese, sync packaging)
- Added detection of samba-official release (so we can keep one spec
  file in sync in both cvs trees)
- Add Distro-detection(tm) (allows us to remove some arbitrary repitition)
- Made patches 20,21,23 (merged upstream), and 22 (breaks pam_smbpass
  compilation, pam_smbpass.so seems to be built correctly without it)
  version-specific
- Removed patches 18,19 (only applicable to 2.2.2)

* Sat Mar 16 2002 Pixel <pixel@mandrakesoft.com> 2.2.3a-10mdk
- fix Patch 7 to fix samba not starting at boot time

* Tue Mar 12 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.3a-9mdk
- Patch 7 to fix samba not starting at boot time (-- Pixel)

* Sat Mar 9 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.3a-8mdk
- Patch 23 from CVS to fix saving changes in printer properties (-- Gerald Carter)

* Fri Mar 8 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.3a-7mdk
- Added a few new codepage/character sets.
- replace deletion of /var/cache/samba by simple backup when removing samba
  to avoid loosing winbind rid->uid map and print driver tdbs.
- Moved /var/cache/samba migration process from %post samba to %post samba-common.
- Moved require xinetd from samba to samba-swat.

* Mon Feb 27 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.3a-6mdk
- Fixed pam_smbpass compiling problem. (-- Ilia Chipitsine)
- moved /var/cache/samba from server to common as it's used by client too.
- symlinked smbwrapper.so back to /usr/bin to fix smbsh pb. (-- Alexander Skwar)
- added %_post/preun_service macro for smb & winbind.

* Fri Feb 22 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.3a-5mdk
- added cli_spoolss_notify patch to prevent smbd dying when a printer
  is opened from Win2k. (-- Gerald Carter)

* Mon Feb 18 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.3a-4mdk
- fixed the chkconfig --reset when upgrading form previos version.
- added correct LDAP schema in example section.

* Fri Feb 08 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.3a-3mdk
- _Really_ suid back smbumount; OK, you can laugh now...

* Fri Feb 08 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.3a-2mdk
- suid back smbumount.

* Thu Feb 07 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.3a-1mdk
- upped to 2.2.3a bugfix version.
- removed suid on smb(u)mount, suid smbmnt instead.

* Mon Feb 04 2002 Buchan Milne <bgmilne@cae.co.za> 2.2.3-2mdk
- Added --without xxx support for all the --with xxx command-
  line options. Now also detects (and warns) when built
  for non-default distro.
- Fix %post -n samba-winbind

* Mon Feb 04 2002 Buchan Milne <bgmilne@cae.co.za> 2.2.3-1mdk
- Samba-2.2.3. Disabled patches 6,18,19, which should have been
  applied in samba CVS.

* Sun Feb 03 2002 Buchan Milne <bgmilne@cae.co.za> 2.2.2-10mdk
- Reenable patches 6 and 19 (applied in CVS, but this is 2.2.2!)
- Added option to use --with xxx when building, options so far
  for mdk72, mdk80, mdk81, mdk82, cooker, ldap, winbind, wins, acl
- Put warning text in %description if the RPM was built with
  non-defaults.

* Mon Jan 21 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.2-9mdk
- Fixed %post scripts here and there.
- samba-common %post scriptlet is now clean (-- thanks Zytho).

* Mon Jan 21 2002 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.2-8mdk
- rebuilt on cooker.
- please test extensively this package,
  but consider our target _is_ 2.2.3.

* Thu Jan 17 2002 Buchan Milne <bgmilne@cae.co.za> 2.2.2-7mdk
- Make a 2.2.2 package for the changes in 2.2.3:
- reenable XFS quota patch, turned off ldap

* Thu Jan 17 2002 Buchan Milne <bgmilne@cae.co.za> 2.2.3-0.20020117mdk
- New scripts for winbind from 3.0alpha spec file

* Wed Jan 16 2002 Buchan Milne <bgmilne@cae.co.za> 2.2.3-0.20020116mdk
- Updated CVS snapshot

* Sun Dec 23 2001 Buchan Milne <bgmilne@cae.co.za> 2.2.3-0.20011222mdk
- New CVS snapshot
- Sync up with changes made in 2.2.2 to support Mandrake 8.0, 7.2
- Added new subpackage for swat
- More %if's for ldap.

* Thu Dec 06 2001 Buchan Milne <bgmilne@cae.co.za> 2.2.3-0.20011205mdk
- Build from CVS snapshot of SAMBA_2_2 to test XFS quotas
- Removed XFS quota patch (applied upstream)

* Wed Dec 05 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.2-6mdk
- fixed typo in system-auth-winbind.pamd (--Thanks J. Gluck).
- fixed %post xxx problem (smb not started in chkconfig --Thanks Viet & B. Kenworthy).

* Fri Nov 23 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.2-5mdk
- Had to remove the network recycle bin patch: it seems to mess up
  file deletion from windows (files appear to be "already in use")

* Tue Nov 13 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.2-4mdk
- added network recycle bin patch:
  <http://www.amherst.edu/~bbstone/howto/samba.html>
- added "recycle bin = .recycled" parameter in smb.conf [homes].
- fixed winbind/nss_wins perms (oh no I don't own that stuff ;o)

* Mon Nov 12 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.2-3mdk
- added %build 8.0 and 7.2, for tweakers to play around.
- changed configure options:
  . removed --with-mmap, --with-netatalk (obsolete).
  . added --with-msdfs, --with-vfs (seems stable, but still need testing).

* Mon Nov 12 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.2-2mdk
- rebuilt with winbind and nss_wins enabled.

* Wed Oct 31 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.2-1mdk
- Rebuilt on cooker.

* Wed Oct 31 2001 Buchan Milne <bgmilne@cae.co.za> 2.2.2-0.992mdk
- Patch for smb.conf to fix incorrect lpq command, typo in winbind,
  and add sample linpopup command. Added print driver directories.
- New XFS quota patch (untested!, samba runs, but do quotas work? We
  can't check yet since the kernel doesn't seem to support XFS quotas!)

* Fri Oct 19 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.2-0.99mdk
- New samba.spec, almost ready for winbind operations. OLA for Buchan Milne
  Who did a tremendous integration work on 2.2.2.
  Rebuild on cooker, please test XFS (ACLs and quotas) again...
  
* Mon Oct 15 2001 Buchan Milne <bgmilne@cae.co.za> 2.2.2-0.9mdk
- Samba-2.2.2. released! Use %defines to determine which subpackages
  are built and which Mandrake release we are buiding on/for (hint: define 
  build_mdk81 1 for Mandrake 8.1 updates)

* Sun Oct 14 2001 Buchan Milne <bgmilne@cae.co.za> 2.2.2-0.20011014mdk
- %post and %postun for nss_wins

* Wed Oct 10 2001 Buchan Milne <bgmilne@cae.co.za> 2.2.2-0.20011010mdk
- New CVS snapshot, /etc/pam.d/system-auth-winbind added
  with configuration to allow easy winbind setup.
  
* Sun Oct 7 2001 Buchan Milne <bgmilne@cae.co.za> 2.2.2-0.20011007mdk
- Added new package nss_wins and moved smbpasswd to common (required by
  winbind).

* Sat Oct 6 2001 Buchan Milne <bgmilne@cae.co.za> 2.2.2-0.20011006mdk
- Added new package winbind.

* Mon Oct 1 2001 Buchan Milne <bgmilne@cae.co.za> 2.2.2-0.20011001mdk
- Removed patch to smb init.d file (applied in cvs)

* Sun Sep 30 2001 Buchan Milne <bgmilne@cae.co.za> 2.2.2-0.20010930mdk
- Added winbind init script, which still needs to check for running nmbd.

* Thu Sep 27 2001 Buchan Milne <bgmilne@cae.co.za> 2.2.2-0.20010927mdk
- Built from samba-2.2.2-pre cvs, added winbindd, wbinfo, nss_winbind and 
  pam_winbind, moved pam_smbpass from samba-common to samba. We still
  need a start-up script for winbind, or need to modify existing one.
  
* Mon Sep 10 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.1a-15mdk
- Enabled acl support (XFS acls now supported by kernel-2.4.8-21mdk thx Chmou)
  Added smbd patch to support XFS quota (Nathan Scott)
  
* Mon Sep 10 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.1a-14mdk
- Oops! smbpasswd created in wrong directory...

* Tue Sep 06 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.1a-13mdk
- Removed a wrong comment in smb.conf.
  Added creation of smbpasswd during install.

* Mon Aug 27 2001 Pixel <pixel@mandrakesoft.com> 2.2.1a-12mdk
- really less verbose %%post

* Sat Aug 25 2001 Geoffrey Lee <snailtalk@mandrakesoft.com> 2.2.1a-11mdk
- Fix shared libs in /usr/bin silliness.

* Thu Aug 23 2001 Pixel <pixel@mandrakesoft.com> 2.2.1a-10mdk
- less verbose %%post

* Wed Aug 22 2001 Buchan Milne <bgmilne@cae.co.za> 2.2.1a-9mdk
- Added smbcacls (missing in %files), modification to smb.conf: ([printers]
  is still needed, even with point-and-print!, user add script should
  use name and not gid, since we may not get the gid . New script for
  putting manpages in place (still need to be added in %files!). Moved
  smbcontrol to sbin and added it and its man page to %files.

* Wed Aug 22 2001 Pixel <pixel@mandrakesoft.com> 2.2.1a-8mdk
- cleanup /var/lib/samba/codepage/src

* Tue Aug 21 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.1a-7mdk
- moved codepage generation to %install and codepage dir to /var/lib/samba

* Tue Aug 21 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.1a-6mdk
- /lib/* was in both samba and samba-common
  Introducing samba-doc: "alas, for the sake of thy modem, shalt thou remember
  when Samba was under the Megabyte..."

* Fri Aug 03 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.1a-5mdk
- Added "the gc touch" to smbinit through the use of killall -0 instead of
  grep cupsd | grep -v grep (too many greps :o)

* Wed Jul 18 2001 Stefan van der Eijk <stefan@eijk.nu> 2.2.1a-4mdk
- BuildRequires: libcups-devel
- Removed BuildRequires: openssl-devel

* Fri Jul 13 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.1a-3mdk
- replace chkconfig --add/del with --level 35 on/reset.

* Fri Jul 13 2001 Geoffrey Lee <snailtalk@mandrakesoft.cm> 2.2.1a-2mdk
- Replace discription s/inetd/xinetd/, we all love xinetd, blah.

* Thu Jul 12 2001 Buchan Milne <bgmilne@cae.co.za> 2.2.1a-1mdk
- Bugfix release. Fixed add user script, added print$ share and printer admin
  We need to test interaction of new print support with CUPS, but printer
  driver uploads should work.

* Wed Jul 11 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.1-17mdk
- fixed smb.conf a bit, rebuilt on cooker.

* Tue Jul 10 2001 Buchan Milne <bgmilne@cae.co.za> 2.2.1-16mdk
- Finally, samba 2.2.1 has actually been release. At least we were ready!
  Cleaned up smb.conf, and added some useful entries for domain controlling.
  Migrated changes made in samba's samba2.spec for 2.2.1  to this file.
  Added groupadd command in post to create a group for samba machine accounts.
  (We should still check the postun, samba removes pam, logs and cache)

* Tue Jun 26 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.1-15mdk
- fixed smbwrapper compile options.

* Tue Jun 26 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.1-14mdk
- added LFS support.
  added smbwrapper support (smbsh)

* Wed Jun 20 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.1-13mdk
- /sbin/mount.smb and /sbin/mount.smbfs now point to the correct location
  of smbmount (/usr/bin/smbmount)

* Tue Jun 19 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.1-12mdk
- smbmount and smbumount are now in /usr/bin and SUID.
  added ||: to triggerpostun son you don't get error 1 anymore when rpm -e
  Checked the .bz2 sources with file *: everything is OK now (I'm so stupid ;o)!

* Tue Jun 19 2001 Geoffrey Lee <snailtalk@mandrakesoft.com> 2.2.1-11mdk
- s/Copyright/License/;
- Stop Sylvester from pretending .gz source to be .bz2 source via filename
  aka really bzip2 the source.

* Mon Jun 18 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.1-10mdk
- changed Till's startup script modifications: now samba is being reloaded
  automatically 1 minute after it has started (same reasons as below in 9mdk)
  added _post_ and _preun_ for service smb
  fixed creation of /var/lib/samba/{netlogon,profiles} (%dir was missing)

* Thu Jun 14 2001 Till Kamppeter <till@mandrakesoft.com> 2.2.1-9mdk
- Modified the Samba startup script so that in case of CUPS being used as
  printing system Samba only starts when the CUPS daemon is ready to accept
  requests. Otherwise the CUPS queues would not appear as Samba shares.

* Mon Jun 11 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.1-8mdk
- patched smbmount.c to have it call smbmnt in sbin (thanks Seb).

* Wed May 30 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.1-7mdk
- put SWAT menu icons back in place.

* Mon May 28 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.1-6mdk
- OOPS! fixed smbmount symlinks

* Mon May 28 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.1-5mdk
- removed inetd postun script, replaced with xinetd.
  updated binary list (smbcacls...)
  cleaned samba.spec

* Mon May 28 2001 Buchan Milne <bgmilne@cae.co.za> 2.2.1-4mdk
- Changed configure options to point to correct log and codepage directories,
  added crude script to fix logrotate file for new log file names, updated
  patches to work with current CVS.

* Thu May 24 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.1-3mdk
- Cleaned and updated the %files section.

* Sat May 19 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.1-2mdk
- Moved all samba files from /etc to /etc/samba (Thanks DomS!).
  Fixed fixinit patch (/etc/samba/smb.conf)

* Fri May 18 2001 Buchan Milne <bgmilne@cae.co.za> 2.2.1-1mdk
- Now use packaging/Mandrake/smb.conf, removed unused and obsolete
  patches, moved netlogon and profile shares to /var/lib/samba in the
  smb.conf to match the spec file. Added configuration for ntlogon to
  smb.conf. Removed pam-foo, fixinit and makefilepath patches. Removed
  symlink I introduced in 2.2.0-1mdk

* Thu May 3 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.0-5mdk
- Added more configure options. Changed Description field (thx John T).

* Wed Apr 25 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.0-4mdk
- moved netlogon and profiles to /var/lib/samba by popular demand ;o)

* Tue Apr 24 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.0-3mdk
- moved netlogon and profiles back to /home.

* Fri Apr 20 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.2.0-2mdk
- fixed post inetd/xinetd script&

* Thu Apr 19 2001 Buchan Milne <bgmilne@cae.co.za> 2.2.0-1mdk
- Upgrade to 2.2.0. Merged most of 2.0.7-25mdk's patches (beware
  nasty "ln -sf samba-%{ver} ../samba-2.0.7" hack to force some patches
  to take. smbadduser and addtosmbpass seem to have disappeared. Moved
  all Mandrake-specific files to packaging/Mandrake and made patches
  from those shipped with samba. Moved netlogon to /home/samba and added
  /home/samba/profiles. Added winbind,smbfilter and debug2html to make command.

* Thu Apr 12 2001 Frederic Crozat <fcrozat@mandrakesoft.com> 2.0.7-25mdk
- Fix menu entry and provide separate menu entry for GNOME
  (nautilus doesn't support HTTP authentication yet)
- Add icons in package

* Fri Mar 30 2001 Frederic Lepied <flepied@mandrakesoft.com> 2.0.7-24mdk
- use new server macros

* Wed Mar 21 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.0.7-23mdk
- check whether /etc/inetd.conf exists (upgrade) or not (fresh install).

* Thu Mar 15 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.0.7-22mdk
- spec cosmetics, added '-r' option to lpr-cups command line so files are
  removed from /var/spool/samba after printing.

* Tue Mar 06 2001 Sylvestre Taburet <staburet@mandrakesoft.com> 2.0.7-21mdk
- merged last rh patches.

* Thu Nov 23 2000 Sylvestre Taburet <staburet@mandrakesoft.com> 2.0.7-20mdk
- removed dependencies on cups and cups-devel so one can install samba without using cups
- added /home/netlogon

* Mon Nov 20 2000 Till Kamppeter <till@mandrakesoft.com> 2.0.7-19mdk
- Changed default print command in /etc/smb.conf, so that the Windows
  driver of the printer has to be used on the client.
- Fixed bug in smbspool which prevented from printing from a
  Linux-Samba-CUPS client to a Windows server through the guest account.

* Mon Oct 16 2000 Till Kamppeter <till@mandrakesoft.com> 2.0.7-18mdk
- Moved "smbspool" (Samba client of CUPS) to the samba-client package

* Sat Oct 7 2000 Stefan van der Eijk <s.vandereijk@chello.nl> 2.0.7-17mdk
- Added RedHat's "quota" patch to samba-glibc21.patch.bz2, this fixes
  quota related compile problems on the alpha.

* Wed Oct 4 2000 Sylvestre Taburet <staburet@mandrakesoft.com> 2.0.7-16mdk
- Fixed 'guest ok = ok' flag in smb.conf

* Tue Oct 3 2000 Sylvestre Taburet <staburet@mandrakesoft.com> 2.0.7-15mdk
- Allowed guest account to print in smb.conf
- added swat icon in menu

* Tue Oct 3 2000 Sylvestre Taburet <staburet@mandrakesoft.com> 2.0.7-14mdk
- Removed rh ssl patch and --with-ssl flag: not appropriate for 7.2

* Tue Oct 3 2000 Sylvestre Taburet <staburet@mandrakesoft.com> 2.0.7-13mdk
- Changed fixinit patch.
- Changed smb.conf for better CUPS configuration.
- Thanks Fred for doing this ---vvv.

* Tue Oct  3 2000 Frederic Lepied <flepied@mandrakesoft.com> 2.0.7-12mdk
- menu entry for web configuration tool.
- merge with rh: xinetd + ssl + pam_stack.
- Added smbadduser rh-bugfix w/o relocation of config-files.

* Mon Oct  2 2000 Frederic Lepied <flepied@mandrakesoft.com> 2.0.7-11mdk
- added build requires on cups-devel and pam-devel.

* Mon Oct  2 2000 Till Kamppeter <till@mandrakesoft.com> 2.0.7-10mdk
- Fixed smb.conf entry for CUPS: "printcap name = lpstat", "lpstats" was
  wrong.

* Mon Sep 25 2000 Sylvestre Taburet <staburet@mandrakesoft.com> 2.0.7-9mdk
- Cosmetic changes to make rpmlint more happy

* Wed Sep 11 2000 Sylvestre Taburet <staburet@mandrakesoft.com> 2.0.7-8mdk
- added linkage to the using_samba book in swat

* Fri Sep 01 2000 Sylvestre Taburet <staburet@mandrakesoft.com> 2.0.7-7mdk
- Added CUPS support to smb.conf
- Added internationalization options to smb.conf [Global]

* Wed Aug 30 2000 Till Kamppeter <till@mandrakesoft.com> 2.0.7-6mdk
- Put "smbspool" to the files to install

* Wed Aug 30 2000 Sylvestre Taburet <staburet@mandrakesoft.com> 2.0.7-5mdk
- Did some cleaning in the patches

* Fri Jul 28 2000 Sylvestre Taburet <staburet@mandrakesoft.com> 2.0.7-4mdk
- relocated man pages from /usr/man to /usr/share/man for compatibility reasons

* Fri Jul 28 2000 Sylvestre Taburet <staburet@mandrakesoft.com> 2.0.7-3mdk
- added make_unicodemap and build of unicode_map.$i in the spec file

* Fri Jul 28 2000 Sylvestre Taburet <staburet@mandrakesoft.com> 2.0.7-2mdk
- renamed /etc/codepage/codepage.$i into /etc/codepage/unicode_map.$i to fix smbmount bug.

* Fri Jul 07 2000 Sylvestre Taburet <staburet@mandrakesoft.com> 2.0.7-1mdk
- 2.0.7

* Wed Apr 05 2000 Francis Galiegue <fg@mandrakesoft.com> 2.0.6-4mdk

- Titi sucks, does not put versions in changelog
- Fixed groups for -common and -client
- /usr/sbin/samba is no config file

* Thu Mar 23 2000 Thierry Vignaud <tvignaud@mandrakesoft.com>
- fix buggy post install script (pixel)

* Fri Mar 17 2000 Francis Galiegue <francis@mandrakesoft.com> 2.0.6-2mdk

- Changed group according to 7.1 specs
- Some spec file changes
- Let spec-helper do its job

* Thu Nov 25 1999 Chmouel Boudjnah <chmouel@mandrakesoft.com>
- 2.0.6.

* Tue Nov  2 1999 Chmouel Boudjnah <chmouel@mandrakesoft.com>
- Merge with rh changes.
- Split in 3 packages.

* Fri Aug 13 1999 Pablo Saratxaga <pablo@@mandrakesoft.com>
- corrected a bug with %post (the $1 parameter is "1" in case of
  a first install, not "0". That parameter is the number of packages
  of the same name that will exist after running all the steps if nothing
  is removed; so it is "1" after first isntall, "2" for a second install
  or an upgrade, and "0" for a removal)

* Wed Jul 28 1999 Pablo Saratxaga <pablo@@mandrakesoft.com>
- made smbmnt and smbumount suid root, and only executable by group 'smb'
  add to 'smb' group any user that should be allowed to mount/unmount
  SMB shared directories

* Fri Jul 23 1999 Chmouel Boudjnah <chmouel@mandrakesoft.com>
- 2.0.5a (bug security fix).

* Wed Jul 21 1999 Axalon Bloodstone <axalon@linux-mandrake.com>
- 2.0.5
- cs/da/de/fi/fr/it/tr descriptions/summaries

* Sun Jun 13 1999 Bernhard Rosenkr�nzer <bero@mandrakesoft.com>
- 2.0.4b
- recompile on a system that works ;)

* Wed Apr 21 1999 Chmouel Boudjnah <chmouel@mandrakesoft.com>
- Mandrake adaptations.
- Bzip2 man-pages.

* Fri Mar 26 1999 Bill Nottingham <notting@redhat.com>
- add a mount.smb to make smb mounting a little easier.
- smb filesystems apparently do not work on alpha. Oops.

* Thu Mar 25 1999 Bill Nottingham <notting@redhat.com>
- always create codepages

* Tue Mar 23 1999 Bill Nottingham <notting@redhat.com>
- logrotate changes

* Sun Mar 21 1999 Cristian Gafton <gafton@redhat.com>
- auto rebuild in the new build environment (release 3)

* Fri Mar 19 1999 Preston Brown <pbrown@redhat.com>
- updated init script to use graceful restart (not stop/start)

* Tue Mar  9 1999 Bill Nottingham <notting@redhat.com>
- update to 2.0.3

* Thu Feb 18 1999 Bill Nottingham <notting@redhat.com>
- update to 2.0.2

* Mon Feb 15 1999 Bill Nottingham <notting@redhat.com>
- swat swat

* Tue Feb  9 1999 Bill Nottingham <notting@redhat.com>
- fix bash2 breakage in post script

* Fri Feb  5 1999 Bill Nottingham <notting@redhat.com>
- update to 2.0.0

* Mon Oct 12 1998 Cristian Gafton <gafton@redhat.com>
- make sure all binaries are stripped

* Thu Sep 17 1998 Jeff Johnson <jbj@redhat.com>
- update to 1.9.18p10.
- fix %triggerpostun.

* Tue Jul 07 1998 Erik Troan <ewt@redhat.com>
- updated postun triggerscript to check $0
- clear /etc/codepages from %preun instead of %postun

* Mon Jun 08 1998 Erik Troan <ewt@redhat.com>
- made the %postun script a tad less agressive; no reason to remove
  the logs or lock file (after all, if the lock file is still there,
  samba is still running)
- the %postun and %preun should only exectute if this is the final
  removal
- migrated %triggerpostun from Red Hat's samba package to work around
  packaging problems in some Red Hat samba releases

* Sun Apr 26 1998 John H Terpstra <jht@samba.anu.edu.au>
- minor tidy up in preparation for release of 1.9.18p5
- added findsmb utility from SGI package

* Wed Mar 18 1998 John H Terpstra <jht@samba.anu.edu.au>
- Updated version and codepage info.
- Release to test name resolve order

* Sat Jan 24 1998 John H Terpstra <jht@samba.anu.edu.au>
- Many optimisations (some suggested by Manoj Kasichainula <manojk@io.com>
- Use of chkconfig in place of individual symlinks to /etc/rc.d/init/smb
- Compounded make line
- Updated smb.init restart mechanism
- Use compound mkdir -p line instead of individual calls to mkdir
- Fixed smb.conf file path for log files
- Fixed smb.conf file path for incoming smb print spool directory
- Added a number of options to smb.conf file
- Added smbadduser command (missed from all previous RPMs) - Doooh!
- Added smbuser file and smb.conf file updates for username map
