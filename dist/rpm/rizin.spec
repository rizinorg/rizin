Name:           rizin
Summary:        UNIX-like reverse engineering framework and command-line tool-set
Version:        0.3.0
URL:            https://rizin.re/
VCS:            https://github.com/rizinorg/rizin

%global         gituser         rizinorg
%global         gitname         rizin
%global         rel             1
%global         shortversion    %(c=%{version}; echo ${c} | cut -d'.' -f-2)

Release:        0%{rel}%{?dist}
Source0:        https://github.com/%{gituser}/%{gitname}/releases/download/v%{version}/%{name}-src-v%{version}.tar.xz

License:        LGPLv3+ and GPLv2+ and BSD and MIT and ASL 2.0 and MPLv2.0 and zlib

BuildRequires:  gcc
BuildRequires:  meson >= 0.55.0
%if 0%{?suse_version}
BuildRequires:  ninja
%else
BuildRequires:  ninja-build
%endif
BuildRequires:  pkgconfig

Requires:       %{name}-common = %{version}-%{release}


%description
Rizin is a free and open-source Reverse Engineering framework, providing a
complete binary analysis experience with features like Disassembler,
Hexadecimal editor, Emulation, Binary inspection, Debugger, and more.

Rizin is a fork of radare2 with a focus on usability, working features and code
cleanliness.


%package devel
Summary:        Development files for the rizin package
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       file-devel
Requires:       openssl-devel

%description devel
Development files for the rizin package. See rizin package for more
information.


%package common
Summary:        Arch-independent SDB files for the rizin package
BuildArch:      noarch
Requires:       %{name} = %{version}-%{release}

%description common
Arch-independent SDB files used by rizin package. See rizin package for more
information


%prep
# Build from git release version
%setup -n %{name}-v%{version}

%build
# Whereever possible use the system-wide libraries instead of bundles
%meson \
%ifarch s390x
    -Ddebugger=false \
%endif
    -Denable_tests=false \
    -Denable_rz_test=false \
    -Dlocal=disabled \
    -Dpackager="RizinOrg" \
    -Dpackager_version="%{version}-%{release}"
%meson_build

%install
%meson_install
%if 0%{?suse_version} || (0%{?centos} && 0%{?centos} < 8)
%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig
%else
%ldconfig_scriptlets
%endif

%check
# Do not run the unit testsuite yet - it pulls another big repository
# https://github.com/rizinorg/rizin-testbins from github

%files
%doc CONTRIBUTING.md DEVELOPERS.md README.md SECURITY.md BUILDING.md
%license COPYING COPYING.LESSER
%{_bindir}/r*
%{_libdir}/librz_*.so.%{version}*
%{_libdir}/librz_*.so.%{shortversion}
%{_mandir}/man1/rizin.1.*
%{_mandir}/man1/rz*.1.*
%{_mandir}/man7/rz-esil.7.*

%files devel
%{_includedir}/librz
%{_libdir}/librz*.so
%{_libdir}/pkgconfig/*.pc
%{_libdir}/cmake/**/*.cmake
%dir %{_libdir}/cmake
%dir %{_libdir}/cmake/**


%files common
%{_datadir}/%{name}/asm
%{_datadir}/%{name}/cons
%{_datadir}/%{name}/flag
%{_datadir}/%{name}/format
%{_datadir}/%{name}/fortunes
%{_datadir}/%{name}/hud
%{_datadir}/%{name}/magic
%{_datadir}/%{name}/opcodes
%{_datadir}/%{name}/reg
%{_datadir}/%{name}/syscall
%{_datadir}/%{name}/types
%dir %{_datadir}/%{name}


%changelog
* Mon Sep 27 2021 Riccardo Schirone <rschirone91@gmail.com> - 0.0.5-1
- Initial spec file from upstream
