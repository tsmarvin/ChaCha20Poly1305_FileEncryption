# ChaCha20Poly1305_FileEncryption
This is an example project showing how to encrypt and decrypt files using the new dotnet 6 System.Security.Cryptography [ChaCha20Poly1305](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.chacha20poly1305) class.

The FileEncryption directory contains the primary assembly.  While, as the name suggests, the ChaCha20Poly1305FileEncryptionExample directory contains an example console app that show's how to use the ChaCha20Poly1305FileEncryption class.


[dotnet 6](https://devblogs.microsoft.com/dotnet/announcing-net-6/) is brand new and with it comes support for a new AEAD algorithm that can be used as an alternative to the aes algorithms.  
Note that ChaCha20Poly1305 cryptography is not supported on all platforms yet.  

The original dotnet api proposal can be [found here](https://github.com/dotnet/runtime/issues/45130#issue-749152031).  
