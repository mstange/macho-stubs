# macho-stubs

When a sampling profiler interrupts a macOS program, sometimes the instruction pointer will be in the `__stubs` section of a binary. This happens when the program is about to call a lazily-bound function from a different library: Each "stub" function loads an address from the `__DATA` segment and jumps to it. This address has been updated to point to the correct destination (maybe by a `__stub_helper` function?).

I would like to be able to map addresses from the `__stubs` section to the name of the function that is about to be called.

This repo contains an attempt to get a list of these stubs. It at least tells us where in the `__DATA` segment each to-be-updated pointer is. But it doesn't tell us where the stub functions are.

The code in this repo is based on [this stackoverflow answer from 2016](https://reverseengineering.stackexchange.com/a/14064).

## Run

```
% cargo run -- `which rustup`
Bind symbols:
segment 2 + 0x30: _kSecRandomDefault (from library 1)
segment 2 + 0x8: _kCFAllocatorDefault (from library 2)
segment 2 + 0x8: _kCFAllocatorNull (from library 2)
segment 2 + 0x8: _kCFErrorDomainOSStatus (from library 2)
segment 2 + 0x8: _kCFTypeArrayCallBacks (from library 2)
segment 2 - 0x28: ___chkstk_darwin (from library 5)
segment 2 - 0x28: ___stack_chk_guard (from library 5)
segment 3 + 0x6d8: __tlv_bootstrap (from library 5)
segment 3 + 0x6f0: __tlv_bootstrap (from library 5)
segment 3 + 0x708: __tlv_bootstrap (from library 5)
segment 3 + 0x720: __tlv_bootstrap (from library 5)
segment 3 + 0x738: __tlv_bootstrap (from library 5)
segment 3 + 0x750: __tlv_bootstrap (from library 5)
segment 3 + 0x768: __tlv_bootstrap (from library 5)
segment 3 + 0x780: __tlv_bootstrap (from library 5)
segment 3 + 0x798: __tlv_bootstrap (from library 5)
segment 3 + 0x7b0: __tlv_bootstrap (from library 5)
segment 3 + 0x7c8: __tlv_bootstrap (from library 5)
segment 3 + 0x7e0: __tlv_bootstrap (from library 5)
segment 3 + 0x7f8: __tlv_bootstrap (from library 5)
segment 3 + 0x810: __tlv_bootstrap (from library 5)
segment 3 + 0x828: __tlv_bootstrap (from library 5)
segment 3 + 0x840: __tlv_bootstrap (from library 5)
segment 3 + 0x858: __tlv_bootstrap (from library 5)
segment 3 + 0x870: __tlv_bootstrap (from library 5)
segment 3 + 0x888: __tlv_bootstrap (from library 5)
segment 3 + 0x8a0: __tlv_bootstrap (from library 5)
segment 2 + 0x40: _vm_page_size (from library 5)
segment 2 + 0x40: dyld_stub_binder (from library 5)
Weak bind symbols:
No weak bind symbols.
Lazy bind symbols:
segment 3 + 0x0: _CFArrayCreate (from library 2)
segment 3 + 0x8: _CFArrayGetCount (from library 2)
segment 3 + 0x10: _CFArrayGetValueAtIndex (from library 2)
segment 3 + 0x18: _CFDataGetBytePtr (from library 2)
segment 3 + 0x20: _CFDataGetLength (from library 2)
segment 3 + 0x28: _CFDictionaryGetValueIfPresent (from library 2)
segment 3 + 0x30: _CFEqual (from library 2)
segment 3 + 0x38: _CFErrorCreate (from library 2)
segment 3 + 0x40: _CFErrorGetCode (from library 2)
segment 3 + 0x48: _CFNumberGetValue (from library 2)
segment 3 + 0x50: _CFRelease (from library 2)
segment 3 + 0x58: _CFRetain (from library 2)
segment 3 + 0x60: _CFStringCreateWithBytes (from library 2)
segment 3 + 0x68: _CFStringCreateWithBytesNoCopy (from library 2)
segment 3 + 0x70: _CFStringGetBytes (from library 2)
segment 3 + 0x78: _CFStringGetCStringPtr (from library 2)
segment 3 + 0x80: _CFStringGetLength (from library 2)
segment 3 + 0x88: _SSLClose (from library 1)
segment 3 + 0x90: _SSLCopyPeerTrust (from library 1)
segment 3 + 0x98: _SSLCreateContext (from library 1)
segment 3 + 0xa0: _SSLGetBufferedReadSize (from library 1)
segment 3 + 0xa8: _SSLGetConnection (from library 1)
segment 3 + 0xb0: _SSLGetEnabledCiphers (from library 1)
segment 3 + 0xb8: _SSLGetNumberEnabledCiphers (from library 1)
segment 3 + 0xc0: _SSLGetSessionState (from library 1)
segment 3 + 0xc8: _SSLHandshake (from library 1)
segment 3 + 0xd0: _SSLRead (from library 1)
segment 3 + 0xd8: _SSLSetCertificate (from library 1)
segment 3 + 0xe0: _SSLSetConnection (from library 1)
segment 3 + 0xe8: _SSLSetEnabledCiphers (from library 1)
segment 3 + 0xf0: _SSLSetIOFuncs (from library 1)
segment 3 + 0xf8: _SSLSetPeerDomainName (from library 1)
segment 3 + 0x100: _SSLSetProtocolVersionMax (from library 1)
segment 3 + 0x108: _SSLSetProtocolVersionMin (from library 1)
segment 3 + 0x110: _SSLSetSessionOption (from library 1)
segment 3 + 0x118: _SSLWrite (from library 1)
segment 3 + 0x120: _SecCertificateCopyData (from library 1)
segment 3 + 0x128: _SecCopyErrorMessageString (from library 1)
segment 3 + 0x130: _SecPolicyCreateSSL (from library 1)
segment 3 + 0x138: _SecRandomCopyBytes (from library 1)
segment 3 + 0x140: _SecTrustEvaluate (from library 1)
segment 3 + 0x148: _SecTrustSetAnchorCertificates (from library 1)
segment 3 + 0x150: _SecTrustSetAnchorCertificatesOnly (from library 1)
segment 3 + 0x158: _SecTrustSetPolicies (from library 1)
segment 3 + 0x160: _SecTrustSettingsCopyCertificates (from library 1)
segment 3 + 0x168: _SecTrustSettingsCopyTrustSettings (from library 1)
segment 3 + 0x170: __NSGetArgc (from library 5)
segment 3 + 0x178: __NSGetArgv (from library 5)
segment 3 + 0x180: __NSGetEnviron (from library 5)
segment 3 + 0x188: __NSGetExecutablePath (from library 5)
segment 3 + 0x190: __Unwind_Backtrace (from library 5)
segment 3 + 0x198: __Unwind_DeleteException (from library 5)
segment 3 + 0x1a0: __Unwind_GetCFA (from library 5)
segment 3 + 0x1a8: __Unwind_GetDataRelBase (from library 5)
segment 3 + 0x1b0: __Unwind_GetIP (from library 5)
segment 3 + 0x1b8: __Unwind_GetIPInfo (from library 5)
segment 3 + 0x1c0: __Unwind_GetLanguageSpecificData (from library 5)
segment 3 + 0x1c8: __Unwind_GetRegionStart (from library 5)
segment 3 + 0x1d0: __Unwind_GetTextRelBase (from library 5)
segment 3 + 0x1d8: __Unwind_RaiseException (from library 5)
segment 3 + 0x1e0: __Unwind_Resume (from library 5)
segment 3 + 0x1e8: __Unwind_SetGR (from library 5)
segment 3 + 0x1f0: __Unwind_SetIP (from library 5)
segment 3 + 0x1f8: ___assert_rtn (from library 5)
segment 3 + 0x200: ___error (from library 5)
segment 3 + 0x208: ___memcpy_chk (from library 5)
segment 3 + 0x210: ___stack_chk_fail (from library 5)
segment 3 + 0x218: __dyld_get_image_header (from library 5)
segment 3 + 0x220: __dyld_get_image_name (from library 5)
segment 3 + 0x228: __dyld_get_image_vmaddr_slide (from library 5)
segment 3 + 0x230: __dyld_image_count (from library 5)
segment 3 + 0x238: __exit (from library 5)
segment 3 + 0x240: __tlv_atexit (from library 5)
segment 3 + 0x248: _abort (from library 5)
segment 3 + 0x250: _bind (from library 5)
segment 3 + 0x258: _bzero (from library 5)
segment 3 + 0x260: _calloc (from library 5)
segment 3 + 0x268: _chdir (from library 5)
segment 3 + 0x270: _chmod (from library 5)
segment 3 + 0x278: _close (from library 5)
segment 3 + 0x280: _closedir (from library 5)
segment 3 + 0x288: _connect (from library 5)
segment 3 + 0x290: _copyfile_state_alloc (from library 5)
segment 3 + 0x298: _copyfile_state_free (from library 5)
segment 3 + 0x2a0: _copyfile_state_get (from library 5)
segment 3 + 0x2a8: _curl_easy_cleanup (from library 3)
segment 3 + 0x2b0: _curl_easy_getinfo (from library 3)
segment 3 + 0x2b8: _curl_easy_init (from library 3)
segment 3 + 0x2c0: _curl_easy_perform (from library 3)
segment 3 + 0x2c8: _curl_easy_setopt (from library 3)
segment 3 + 0x2d0: _curl_easy_strerror (from library 3)
segment 3 + 0x2d8: _curl_formfree (from library 3)
segment 3 + 0x2e0: _curl_global_init (from library 3)
segment 3 + 0x2e8: _curl_slist_free_all (from library 3)
segment 3 + 0x2f0: _dlsym (from library 5)
segment 3 + 0x2f8: _dup (from library 5)
segment 3 + 0x300: _dup2 (from library 5)
segment 3 + 0x308: _execvp (from library 5)
segment 3 + 0x310: _exit (from library 5)
segment 3 + 0x318: _fchmod (from library 5)
segment 3 + 0x320: _fcntl (from library 5)
segment 3 + 0x328: _fcopyfile (from library 5)
segment 3 + 0x330: _fmod (from library 5)
segment 3 + 0x338: _fork (from library 5)
segment 3 + 0x340: _free (from library 5)
segment 3 + 0x348: _freeaddrinfo (from library 5)
segment 3 + 0x350: _fstat (from library 5)
segment 3 + 0x358: _gai_strerror (from library 5)
segment 3 + 0x360: _getaddrinfo (from library 5)
segment 3 + 0x368: _getcwd (from library 5)
segment 3 + 0x370: _getenv (from library 5)
segment 3 + 0x378: _geteuid (from library 5)
segment 3 + 0x380: _getpeername (from library 5)
segment 3 + 0x388: _getpid (from library 5)
segment 3 + 0x390: _getpwuid_r (from library 5)
segment 3 + 0x398: _getrlimit (from library 5)
segment 3 + 0x3a0: _getsockopt (from library 5)
segment 3 + 0x3a8: _gettimeofday (from library 5)
segment 3 + 0x3b0: _getuid (from library 5)
segment 3 + 0x3b8: _host_statistics (from library 5)
segment 3 + 0x3c0: _ioctl (from library 5)
segment 3 + 0x3c8: _isatty (from library 5)
segment 3 + 0x3d0: _kevent (from library 5)
segment 3 + 0x3d8: _kill (from library 5)
segment 3 + 0x3e0: _kqueue (from library 5)
segment 3 + 0x3e8: _linkat (from library 5)
segment 3 + 0x3f0: _lseek (from library 5)
segment 3 + 0x3f8: _lstat (from library 5)
segment 3 + 0x400: _mach_absolute_time (from library 5)
segment 3 + 0x408: _mach_host_self (from library 5)
segment 3 + 0x410: _mach_timebase_info (from library 5)
segment 3 + 0x418: _malloc (from library 5)
segment 3 + 0x420: _memchr (from library 5)
segment 3 + 0x428: _memcmp (from library 5)
segment 3 + 0x430: _memcpy (from library 5)
segment 3 + 0x438: _memmove (from library 5)
segment 3 + 0x440: _memset (from library 5)
segment 3 + 0x448: _memset_pattern16 (from library 5)
segment 3 + 0x450: _mkdir (from library 5)
segment 3 + 0x458: _mmap (from library 5)
segment 3 + 0x460: _mprotect (from library 5)
segment 3 + 0x468: _munmap (from library 5)
segment 3 + 0x470: _nanosleep (from library 5)
segment 3 + 0x478: _open (from library 5)
segment 3 + 0x480: _opendir (from library 5)
segment 3 + 0x488: _pipe (from library 5)
segment 3 + 0x490: _poll (from library 5)
segment 3 + 0x498: _posix_memalign (from library 5)
segment 3 + 0x4a0: _posix_spawn_file_actions_adddup2 (from library 5)
segment 3 + 0x4a8: _posix_spawn_file_actions_destroy (from library 5)
segment 3 + 0x4b0: _posix_spawn_file_actions_init (from library 5)
segment 3 + 0x4b8: _posix_spawnattr_destroy (from library 5)
segment 3 + 0x4c0: _posix_spawnattr_init (from library 5)
segment 3 + 0x4c8: _posix_spawnattr_setflags (from library 5)
segment 3 + 0x4d0: _posix_spawnattr_setsigdefault (from library 5)
segment 3 + 0x4d8: _posix_spawnattr_setsigmask (from library 5)
segment 3 + 0x4e0: _posix_spawnp (from library 5)
segment 3 + 0x4e8: _pthread_atfork (from library 5)
segment 3 + 0x4f0: _pthread_attr_destroy (from library 5)
segment 3 + 0x4f8: _pthread_attr_init (from library 5)
segment 3 + 0x500: _pthread_attr_setstacksize (from library 5)
segment 3 + 0x508: _pthread_cond_broadcast (from library 5)
segment 3 + 0x510: _pthread_cond_destroy (from library 5)
segment 3 + 0x518: _pthread_cond_signal (from library 5)
segment 3 + 0x520: _pthread_cond_timedwait (from library 5)
segment 3 + 0x528: _pthread_cond_wait (from library 5)
segment 3 + 0x530: _pthread_create (from library 5)
segment 3 + 0x538: _pthread_detach (from library 5)
segment 3 + 0x540: _pthread_get_stackaddr_np (from library 5)
segment 3 + 0x548: _pthread_get_stacksize_np (from library 5)
segment 3 + 0x550: _pthread_join (from library 5)
segment 3 + 0x558: _pthread_mutex_destroy (from library 5)
segment 3 + 0x560: _pthread_mutex_init (from library 5)
segment 3 + 0x568: _pthread_mutex_lock (from library 5)
segment 3 + 0x570: _pthread_mutex_trylock (from library 5)
segment 3 + 0x578: _pthread_mutex_unlock (from library 5)
segment 3 + 0x580: _pthread_mutexattr_destroy (from library 5)
segment 3 + 0x588: _pthread_mutexattr_init (from library 5)
segment 3 + 0x590: _pthread_mutexattr_settype (from library 5)
segment 3 + 0x598: _pthread_rwlock_rdlock (from library 5)
segment 3 + 0x5a0: _pthread_rwlock_unlock (from library 5)
segment 3 + 0x5a8: _pthread_rwlock_wrlock (from library 5)
segment 3 + 0x5b0: _pthread_self (from library 5)
segment 3 + 0x5b8: _pthread_setname_np (from library 5)
segment 3 + 0x5c0: _pthread_sigmask (from library 5)
segment 3 + 0x5c8: _read (from library 5)
segment 3 + 0x5d0: _readdir_r (from library 5)
segment 3 + 0x5d8: _readlink (from library 5)
segment 3 + 0x5e0: _readv (from library 5)
segment 3 + 0x5e8: _realloc (from library 5)
segment 3 + 0x5f0: _realpath$DARWIN_EXTSN (from library 5)
segment 3 + 0x5f8: _recv (from library 5)
segment 3 + 0x600: _rename (from library 5)
segment 3 + 0x608: _rmdir (from library 5)
segment 3 + 0x610: _sched_yield (from library 5)
segment 3 + 0x618: _send (from library 5)
segment 3 + 0x620: _setgid (from library 5)
segment 3 + 0x628: _setgroups (from library 5)
segment 3 + 0x630: _setsockopt (from library 5)
segment 3 + 0x638: _setuid (from library 5)
segment 3 + 0x640: _shutdown (from library 5)
segment 3 + 0x648: _sigaction (from library 5)
segment 3 + 0x650: _sigaddset (from library 5)
segment 3 + 0x658: _sigaltstack (from library 5)
segment 3 + 0x660: _sigemptyset (from library 5)
segment 3 + 0x668: _signal (from library 5)
segment 3 + 0x670: _socket (from library 5)
segment 3 + 0x678: _socketpair (from library 5)
segment 3 + 0x680: _stat (from library 5)
segment 3 + 0x688: _strerror_r (from library 5)
segment 3 + 0x690: _strlen (from library 5)
segment 3 + 0x698: _symlink (from library 5)
segment 3 + 0x6a0: _sysconf (from library 5)
segment 3 + 0x6a8: _sysctl (from library 5)
segment 3 + 0x6b0: _uname (from library 5)
segment 3 + 0x6b8: _unlink (from library 5)
segment 3 + 0x6c0: _waitpid (from library 5)
segment 3 + 0x6c8: _write (from library 5)
segment 3 + 0x6d0: _writev (from library 5)
```
