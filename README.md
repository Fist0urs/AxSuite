AxSuite
=======

AxSuite is a toolset aimed to retrieve in-memory secrets saved by AxCrypt (http://www.axantum.com/axcrypt/)
These secrets are sufficient enough to decrypt archives protected with AxCrypt, but you can also check
my implementation of the algorithm within John The Ripper bleeding-jumbo (https://github.com/magnumripper/JohnTheRipper)
and hashcat (https://github.com/hashcat/hashcat) if you really need to retrieve the associated password.


Author
------
- Fist0urs, eddy (dot) maaalou (at) gmail (dot) com


AxCreep
-------
Prerequisites :
- An access to the system you want AxCreep to retrieve in-memory secrets
- Same Integrity Level than the AxCrypt process

AxCrypt uses a file handle to store these secrets (if user checked the option to remember secrets) 
on the filesystem and this handle set permissions to duplicate handle for the group "Everyone".
So, having the right integrity level allows you to retrieve these secrets without injecting
your payload in AxCrypt's memory, thus 100% reliable.


AxCarve
-------
Prerequisites :
- An access to the system you want AxCarve to retrieve in-memory secrets
- Administrator privileges

As stated above, AxCrypt stores secrets on the filesystem. All we need
is to carve it searching to signature.

There can be some false positives: when user checks "erase secrets", AxCrypt
puts some random stuff instead of the secret, but headers are still here.


Install
-------
AxCreep and AxCarve are standalone PE


HOWTO
-----
All you have to do is launch binaries:
- AxCreep will display on stdout the RawSha1 (you need to put it on right format with jtr and hashcat)
- AxCarve will put results in the TEMP directory

TODO
----
- Clean code for decryption only having the secrets and commit it.
