#TODO: Build EPEL8 package once all deps are built

%global srcname paramiko

Name:          python-%{srcname}
Version:       2.6.0
Release:       5%{?dist}
Summary:       SSH2 protocol library for python

# No version specified.
License:       LGPLv2+
URL:           https://github.com/paramiko/paramiko
Source0:       %{url}/archive/%{version}/%{srcname}-%{version}.tar.gz

BuildArch:     noarch

%global paramiko_desc \
Paramiko (a combination of the Esperanto words for "paranoid" and "friend") is\
a module for python 2.3 or greater that implements the SSH2 protocol for secure\
(encrypted and authenticated) connections to remote machines. Unlike SSL (aka\
TLS), the SSH2 protocol does not require hierarchical certificates signed by a\
powerful central authority. You may know SSH2 as the protocol that replaced\
telnet and rsh for secure access to remote shells, but the protocol also\
includes the ability to open arbitrary channels to remote services across an\
encrypted tunnel (this is how sftp works, for example).

%description

%package -n python%{python3_pkgversion}-%{srcname}
Summary:       SSH2 protocol library for python
%{?python_provide:%python_provide python%{python3_pkgversion}-%{srcname}}
BuildRequires: python%{python3_pkgversion}-devel
BuildRequires: python%{python3_pkgversion}-setuptools
BuildRequires: python%{python3_pkgversion}-bcrypt >= 3.1.3
BuildRequires: python%{python3_pkgversion}-cryptography >= 2.5
BuildRequires: python%{python3_pkgversion}-mock >= 2.0.0
BuildRequires: python%{python3_pkgversion}-pynacl >= 1.0.1
BuildRequires: python%{python3_pkgversion}-pytest
BuildRequires: python%{python3_pkgversion}-pytest-relaxed >= 1.1.5
Requires:      python%{python3_pkgversion}-bcrypt >= 3.1.3
Requires:      python%{python3_pkgversion}-cryptography >= 2.5
Requires:      python%{python3_pkgversion}-pynacl >= 1.0.1

%description -n python%{python3_pkgversion}-%{srcname}
%{paramiko_desc}

Python 3 version.

%package doc
Summary:       Docs and demo for SSH2 protocol library for python
BuildRequires: /usr/bin/sphinx-build
Requires:      %{name} = %{version}-%{release}

%description doc
%{paramiko_desc}

This is the documentation and demos.

%prep
%autosetup -p1 -n %{srcname}-%{version}

chmod -c a-x demos/*
sed -i -e '/^#!/,1d' demos/*

%build
%py3_build

%install
%py3_install

sphinx-build -b html sites/docs/ html/
rm -f html/.buildinfo

%check
# Remove sftp test (fail under mock)
rm -f tests/test_sftp*.py
PYTHONPATH=%{buildroot}%{python3_sitelib} pytest-%{python3_version}


%files -n python%{python3_pkgversion}-%{srcname}
%license LICENSE
%doc NEWS README.rst
%{python3_sitelib}/%{srcname}-*.egg-info/
%{python3_sitelib}/%{srcname}/

%files doc
%doc html/ demos/

%changelog
* Sun Oct 06 2019 Othman Madjoudj <athmane@fedoraproject.org> - 2.6.0-5
- Drop python2 subpackage since it's eol-ed

* Thu Oct 03 2019 Miro Hrončok <mhroncok@redhat.com> - 2.6.0-4
- Rebuilt for Python 3.8.0rc1 (#1748018)

* Mon Aug 19 2019 Miro Hrončok <mhroncok@redhat.com> - 2.6.0-3
- Rebuilt for Python 3.8

* Fri Jul 26 2019 Fedora Release Engineering <releng@fedoraproject.org> - 2.6.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_31_Mass_Rebuild

* Thu Jun 27 2019 Paul Howarth <paul@city-fan.org> - 2.6.0-1
- Update to 2.6.0
  - Add a new keyword argument to 'SSHClient.connect' and
    '~paramiko.transport.Transport', 'disabled_algorithms', which allows
    selectively disabling one or more kex/key/cipher/etc algorithms; this can
    be useful when disabling algorithms your target server (or client) does not
    support cleanly, or to work around unpatched bugs in Paramiko's own
    implementation thereof (GH#1463)
  - Tweak many exception classes so their string representations are more
    human-friendly; this also includes incidental changes to some 'super()'
    calls (GH#1440, GH#1460)
  - Add backwards-compatible support for the 'gssapi' GSSAPI library, as the
    previous backend ('python-gssapi') has become defunct (GH#584, GH#1166,
    GH#1311)
  - 'SSHClient.exec_command' now returns a new subclass,
    '~paramiko.channel.ChannelStdinFile', rather than a naïve
    '~paramiko.channel.ChannelFile' object for its 'stdin' value, which fixes
    issues such as hangs when running remote commands that read from stdin
    (GH#322)
- Drop gssapi patch as it's no longer needed
- Drop pytest-relaxed patch as it's no longer needed

* Thu Jun 27 2019 Paul Howarth <paul@city-fan.org> - 2.5.1-1
- Update to 2.5.1
  - Fix Ed25519 key handling so certain key comment lengths don't cause
    'SSHException("Invalid key")' (GH#1306, GH#1400)

* Mon Jun 10 2019 Paul Howarth <paul@city-fan.org> - 2.5.0-1
- Update to 2.5.0
  - Add support for encrypt-then-MAC (ETM) schemes and two newer Diffie-Hellman
    group key exchange algorithms ('group14', using SHA256; and 'group16',
    using SHA512)
  - Add support for Curve25519 key exchange
  - Raise Cryptography dependency requirement to version 2.5 (from 1.5) and
    update some deprecated uses of its API
  - Add support for the modern (as of Python 3.3) import location of
    'MutableMapping' (used in host key management) to avoid the old location
    becoming deprecated in Python 3.8
- Drop hard dependency on pyasn1 as it's only needed for optional GSSAPI
  functionality

* Sat Feb 02 2019 Fedora Release Engineering <releng@fedoraproject.org> - 2.4.2-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_30_Mass_Rebuild

* Tue Oct  9 2018 Paul Howarth <paul@city-fan.org> - 2.4.2-1
- Update to 2.4.2
  - Fix exploit (GH#1283, CVE-2018-1000805) in Paramiko’s server mode (not
    client mode) where hostile clients could trick the server into thinking
    they were authenticated without actually submitting valid authentication
  - Modify protocol message handling such that Transport does not respond to
    MSG_UNIMPLEMENTED with its own MSG_UNIMPLEMENTED; this behavior probably
    didn’t cause any outright errors, but it doesn’t seem to conform to the
    RFCs and could cause (non-infinite) feedback loops in some scenarios
    (usually those involving Paramiko on both ends)
  - Add *.pub files to the MANIFEST so distributed source packages contain
    some necessary test assets (GH#1262)
- Test suite now requires mock ≥ 2.0.0

* Sat Jul 14 2018 Fedora Release Engineering <releng@fedoraproject.org> - 2.4.1-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_29_Mass_Rebuild

* Wed Jun 20 2018 Miro Hrončok <mhroncok@redhat.com> - 2.4.1-4
- Rebuilt for Python 3.7
- Remove dependency on on pytest-relaxed

* Fri Mar 16 2018 Paul Howarth <paul@city-fan.org> - 2.4.1-1
- Update to 2.4.1
  - Fix a security flaw (GH#1175, CVE-2018-7750) in Paramiko's server mode
    (this does not impact client use) where authentication status was not
    checked before processing channel-open and other requests typically only
    sent after authenticating
  - Ed25519 auth key decryption raised an unexpected exception when given a
    unicode password string (typical in python 3) (GH#1039)

* Fri Feb 09 2018 Fedora Release Engineering <releng@fedoraproject.org> - 2.4.0-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

* Sat Nov 18 2017 Athmane Madjoudj <athmane@fedoraproject.org> - 2.4.0-2
- Add gssapi patch back since 2.4.0 still not compatible
- Add missing BR (lost during merge)

* Fri Nov 17 2017 Igor Gnatenko <ignatenkobrain@fedoraproject.org> - 2.4.0-1
- Update to 2.4.0

* Wed Nov 15 2017 Athmane Madjoudj <athmane@fedoraproject.org> - 2.4.0-1
- Update to 2.4.0 (rhbz #1513208)
- Revamp check section

* Sun Oct 29 2017 Athmane Madjoudj <athmane@fedoraproject.org> - 2.3.1-3
- Add a patch to disable gssapi on unsupported version (rhbz #1507174)

* Tue Sep 26 2017 Athmane Madjoudj <athmane@fedoraproject.org> - 2.3.1-2
- Remove weak deps, paramiko does not support recent gssapi (rhbz #1496148)

* Sat Sep 23 2017 Athmane Madjoudj <athmane@fedoraproject.org> - 2.3.1-1
- Update to 2.3.1 (rhbz #1494764)

* Wed Sep 20 2017 Paul Howarth <paul@city-fan.org> - 2.3.0-1
- 2.3.0.

* Thu Jul 27 2017 Fedora Release Engineering <releng@fedoraproject.org> - 2.2.1-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

* Wed Jun 14 2017 Paul Howarth <paul@city-fan.org> - 2.2.1-1
- 2.2.1.

* Sun Jun 11 2017 Paul Howarth <paul@city-fan.org> - 2.2.0-1
- 2.2.0.

* Wed Feb 22 2017 Paul Howarth <paul@city-fan.org> - 2.1.2-1
- 2.1.2.

* Sat Feb 11 2017 Fedora Release Engineering <releng@fedoraproject.org> - 2.1.1-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

* Mon Dec 19 2016 Miro Hrončok <mhroncok@redhat.com> - 2.1.1-2
- Rebuild for Python 3.6

* Fri Dec 16 2016 Jon Ciesla <limburgher@gmail.com> - 2.1.1-1
- 2.1.1.

* Fri Dec 09 2016 Jon Ciesla <limburgher@gmail.com> - 2.1.0-1
- 2.1.0.

* Fri Dec 09 2016 Jon Ciesla <limburgher@gmail.com> - 2.0.2-1
- 2.0.2.

* Tue Jul 19 2016 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.0.0-2
- https://fedoraproject.org/wiki/Changes/Automatic_Provides_for_Python_RPM_Packages

* Fri Apr 29 2016 Igor Gnatenko <ignatenko@redhat.com> - 2.0.0-1
- Update to 2.0.0 (RHBZ #1331737)

* Sun Mar 27 2016 Igor Gnatenko <i.gnatenko.brain@gmail.com> - 1.16.0-1
- Update to 1.16.0
- Adopt to new packaging guidelines

* Thu Feb 04 2016 Fedora Release Engineering <releng@fedoraproject.org> - 1.15.2-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

* Tue Nov 10 2015 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.15.2-4
- Rebuilt for https://fedoraproject.org/wiki/Changes/python3.5

* Thu Jun 18 2015 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.15.2-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

* Sun Mar 22 2015 Peter Robinson <pbrobinson@fedoraproject.org> 1.15.2-2
- Use %%license
- Move duplicated docs to single doc sub package
- Remove old F-15 conditionals

* Tue Dec 23 2014 Athmane Madjoudj <athmane@fedoraproject.org> 1.15.2-1
- Update to 1.15.2

* Mon Nov 24 2014 Athmane Madjoudj <athmane@fedoraproject.org> 1.15.1-5
- Add conditional to exclude EL since does not have py3

* Sat Nov 15 2014 Athmane Madjoudj <athmane@fedoraproject.org> 1.15.1-4
- py3dir creation should be in prep section

* Fri Nov 14 2014 Athmane Madjoudj <athmane@fedoraproject.org> 1.15.1-3
- Build each pkg in a clean dir

* Fri Nov 14 2014 Athmane Madjoudj <athmane@fedoraproject.org> 1.15.1-2
- Add support for python3
- Add BR -devel for python macros.

* Fri Oct 17 2014 Jeffrey C. Ollie <jeff@ocjtech.us> - 1.15.1-1
- Update to 1.15.1

* Fri Jun 13 2014 Orion Poplawski <orion@cora.nwra.com> - 1.12.4-1
- Update to 1.12.4

* Sat Jun 07 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.12.2-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Tue Feb 25 2014 Orion Poplawski <orion@cora.nwra.com> - 1.12.2-1
- Update to 1.12.2

* Wed Jan 22 2014 Orion Poplawski <orion@cora.nwra.com> - 1.11.3-1
- Update to 1.11.3

* Mon Oct 21 2013 Orion Poplawski <orion@cora.nwra.com> - 1.11.0-1
- Update to 1.11.0

* Sun Aug 04 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.10.1-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_20_Mass_Rebuild

* Thu May  9 2013 Jeffrey Ollie <jeff@ocjtech.us> - 1.10.1-1
- Update to 1.10.1

* Thu Feb 14 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.9.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

* Wed Jan  2 2013 Jeffrey Ollie <jeff@ocjtech.us> - 1.9.0-1
- Update to 1.9.0

* Sat Jul 21 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.7.7.1-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Sat Jan 14 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.7.7.1-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Wed Jul  6 2011 Jeffrey C. Ollie <jeff@ocjtech.us> - 1.7.7.1-1
- v1.7.7.1 (George) 21may11
- -------------------------
-   * Make the verification phase of SFTP.put optional (Larry Wright)
-   * Patches to fix AIX support (anonymous)
-   * Patch from Michele Bertoldi to allow compression to be turned on in the
-     client constructor.
-   * Patch from Shad Sharma to raise an exception if the transport isn't active
-     when you try to open a new channel.
-   * Stop leaking file descriptors in the SSH agent (John Adams)
-   * More fixes for Windows address family support (Andrew Bennetts)
-   * Use Crypto.Random rather than Crypto.Util.RandomPool
-     (Gary van der Merwe, #271791)
-   * Support for openssl keys (tehfink)
-   * Fix multi-process support by calling Random.atfork (sugarc0de)

* Tue Feb 08 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.7.6-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Tue Jan 4 2011 Toshio Kuratomi <toshio@fedoraproject.org> - 1.7.6-3
- Patch to address deprecation warning from pycrypto
- Simplify build as shown in new python guidelines
- Enable test suite

* Thu Jul 22 2010 David Malcolm <dmalcolm@redhat.com> - 1.7.6-2
- Rebuilt for https://fedoraproject.org/wiki/Features/Python_2.7/MassRebuild

* Mon Nov  2 2009 Jeffrey C. Ollie <jeff@ocjtech.us> - 1.7.6-1
- v1.7.6 (Fanny) 1nov09
- ---------------------
-  * fixed bugs 411099 (sftp chdir isn't unicode-safe), 363163 & 411910 (more
-    IPv6 problems on windows), 413850 (race when server closes the channel),
-    426925 (support port numbers in host keys)

* Tue Oct 13 2009 Jeremy Katz <katzj@fedoraproject.org> - 1.7.5-2
- Fix race condition (#526341)

* Thu Jul 23 2009 Jeffrey C. Ollie <jeff@ocjtech.us> - 1.7.5-1
- v1.7.5 (Ernest) 19jul09
- -----------------------
-  * added support for ARC4 cipher and CTR block chaining (Denis Bernard)
-  * made transport threads daemonize, to fix python 2.6 atexit behavior
-  * support unicode hostnames, and IP6 addresses (Maxime Ripard, Shikhar
-    Bhushan)
-  * various small bug fixes

* Thu Feb 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.7.4-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Mon Feb 16 2009 Jeffrey C. Ollie <jeff@ocjtech.us> - 1.7.4-4
- Add demos as documentation. BZ#485742

* Sat Nov 29 2008 Ignacio Vazquez-Abrams <ivazqueznet+rpm@gmail.com> - 1.7.4-3
- Rebuild for Python 2.6

* Wed Sep  3 2008 Tom "spot" Callaway <tcallawa@redhat.com> - 1.7.4-2
- fix license tag

* Sun Jul  6 2008 Jeffrey C. Ollie <jeff@ocjtech.us> - 1.7.4-1
- Update to 1.7.4

* Mon Mar 24 2008 Jeffrey C. Ollie <jeff@ocjtech.us> - 1.7.3-1
- Update to 1.7.3.

* Tue Jan 22 2008 Jeffrey C. Ollie <jeff@ocjtech.us> - 1.7.2-1
- Update to 1.7.2.
- Remove upstreamed patch.

* Mon Jan 14 2008 Jeffrey C. Ollie <jeff@ocjtech.us> - 1.7.1-3
- Update to latest Python packaging guidelines.
- Apply patch that fixes insecure use of RandomPool.

* Thu Jul 19 2007 Jeffrey C. Ollie <jeff@ocjtech.us> - 1.7.1-2
- Bump rev

* Thu Jul 19 2007 Jeffrey C. Ollie <jeff@ocjtech.us> - 1.7.1-1
- Update to 1.7.1

* Sat Dec 09 2006 Toshio Kuratomi <toshio@tiki-lounge.com> - 1.6.4-1
- Update to 1.6.4
- Upstream is now shipping tarballs
- Bump for python 2.5 in devel

* Mon Oct  9 2006 Jeffrey C. Ollie <jeff@ocjtech.us> - 1.6.2-1
- Update to 1.6.2

* Sat Sep 16 2006 Shahms E. King <shahms@shahms.com> 1.6.1-3
- Rebuild for FC6

* Fri Aug 11 2006 Shahms E. King <shahms@shahms.com> 1.6.1-2
- Include, don't ghost .pyo files per new guidelines

* Tue Aug 08 2006 Shahms E. King <shahms@shahms.com> 1.6.1-1
- Update to new upstream version

* Fri Jun 02 2006 Shahms E. King <shahms@shahms.com> 1.6-1
- Update to new upstream version
- ghost the .pyo files

* Fri May 05 2006 Shahms E. King <shahms@shahms.com> 1.5.4-2
- Fix source line and rebuild

* Fri May 05 2006 Shahms E. King <shahms@shahms.com> 1.5.4-1
- Update to new upstream version

* Wed Apr 12 2006 Shahms E. King <shahms@shahms.com> 1.5.3-1
  - Initial package
