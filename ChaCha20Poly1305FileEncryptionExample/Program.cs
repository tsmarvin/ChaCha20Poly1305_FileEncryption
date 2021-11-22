using FileEncryption;
using System.Security.Cryptography;

namespace ChaCha20Poly1305FileEncryptionExample {
    public class ChaCha20Poly1305Example {

        public static async Task Main(string[] args) {
            string? path = args.Length != 0 ? args[0] : null;

            byte[] Key = new byte[32];
            FileInfo plaintextFile = path == null ? new("Test.xyz") : new(path);
            FileInfo cypherTxtFile = new("test.enc");
            FileInfo decryptedFile = new("test.txt");
            FileInfo keyFile       = new("test.key");

            // Generate Random Key
            RandomNumberGenerator.Create().GetBytes(Key);

            var platformSupported = new ChaCha20Poly1305FileEncryption(true).PlatformSupported;

            if (platformSupported == true) {
                Console.WriteLine("Hurray ChaCha20Poly1305 is supported! Files can be encrypted / decrypted.");
            }

            if (plaintextFile.Exists == false) {
                Console.WriteLine($"Creating Example File To Encrypt: \"{plaintextFile.FullName}\"");
                File.WriteAllText(plaintextFile.FullName, "Test Data To Encrypt!");
            }

            Console.WriteLine($"Encrypting \"{plaintextFile.FullName}\"");
            await ChaCha20Poly1305FileEncryption.Encrypt(Key, plaintextFile, cypherTxtFile, keyFile);
            Console.WriteLine($"File Successfully Encrypted As \"{cypherTxtFile.FullName}\"");

            // Uncomment the following lines to delete the plain text input file after encryption
            //Console.WriteLine($"Deleting plaintext input file \"{plaintextFile.FullName}\"");
            //plaintextFile.Delete();

            Console.WriteLine(
                $"Using Encryption KeyFile (\"{keyFile.FullName}\") to " +
                $"decrypt \"{cypherTxtFile.FullName}\" into \"{decryptedFile.FullName}\"."
            );
            await ChaCha20Poly1305FileEncryption.Decrypt(keyFile, cypherTxtFile, decryptedFile);
            Console.WriteLine($"The contents of \"{plaintextFile.FullName}\" should now match the original contents from \"{cypherTxtFile.FullName}\".");
        }
    }
}
