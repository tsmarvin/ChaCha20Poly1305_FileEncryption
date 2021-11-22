using System.Security.Cryptography;
using FileEncryption.Types;

namespace FileEncryption {
    public class ChaCha20Poly1305FileEncryption {

        private const int MaxValue = 1000000000;

        public  bool  PlatformSupported { get { return _platformSupported; } }
        private bool _platformSupported { get; set; }

        // All methods are static so this CTor does nothing but help avoid another using statement.
        public ChaCha20Poly1305FileEncryption(bool? throwOnUnsupported = null) {
            _platformSupported = ChaCha20Poly1305.IsSupported;
            if (throwOnUnsupported != null && throwOnUnsupported == true && _platformSupported == false) {
                throw new NotSupportedException(
                    "ChaCha20Poly1305 cryptography is not supported on this platform.\n" +
                    "Since dotnet 6 is brand new this isn't available many places yet. See this link for more info on dotnet 6: https://devblogs.microsoft.com/dotnet/announcing-net-6-preview-5/ \n" +
                    "The apiSpec is available here: https://github.com/dotnet/runtime/issues/45130#issue-749152031 \n" +
                    "Once this is generally supported  exceptions may be listed here: https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.chacha20poly1305"
                );
            }
        }

        #region Encryption

        public static async Task Encrypt(
            byte[]    key,
            FileInfo  plaintextFile,
            FileInfo  cypherTxtFile,
            FileInfo? keyFile = null
        ) {
            // Validate Input
            if (File.Exists(plaintextFile.FullName) && plaintextFile.Exists == false) {
                plaintextFile = new(plaintextFile.FullName);
            }

            if (plaintextFile.Exists == false || plaintextFile.Length == 0) {
                throw new ArgumentOutOfRangeException(
                    nameof(plaintextFile),
                    $"PlainTextFile \"{plaintextFile.FullName}\" must exist and have a length greater than 0."
                );
            }

            if (keyFile == null) {
                keyFile = new(cypherTxtFile.FullName + ".key");
            }

            DecryptionData decryptionData = await EncryptFile(key, plaintextFile, cypherTxtFile);

            await File.WriteAllTextAsync(
                keyFile.FullName,
                decryptionData.ToString()
            );
        }

        #region Encryption Helpers

        private static async Task<DecryptionData> EncryptFile(
            byte[]   key,
            FileInfo plaintextFile,
            FileInfo cypherTxtFile
        ) {

            ChaCha20Poly1305        chaPoly        = new(key);
            List<byte[]>            uniqueNonces   = GetNonces(plaintextFile.Length);
            List<DecryptionKeyNote> keyNoteList    = new();
            long                    processedBytes = 0;
            int                     chunkCount     = 1;

            while (processedBytes < plaintextFile.Length) {

                byte[] plaintext = (chunkCount == uniqueNonces.Count) ?
                                    new byte[plaintextFile.Length - processedBytes] :
                                    new byte[MaxValue];

                keyNoteList.Add(
                    await EncryptFileChunk(
                        chaPoly,
                        uniqueNonces[(chunkCount - 1)],
                        plaintext,
                        plaintextFile,
                        cypherTxtFile,
                        chunkCount,
                        processedBytes
                    )
                );

                processedBytes += plaintext.Length;
                chunkCount++;
            }

            return new DecryptionData(key, keyNoteList);
        }


        private static async Task<DecryptionKeyNote> EncryptFileChunk(
            ChaCha20Poly1305 chaPoly,
            byte[]           nonce,
            byte[]           plaintext,
            FileInfo         plaintextFile,
            FileInfo         cypherTxtFile,
            int              order,
            long             offset
        ) {
            // Initialize
            byte[] tag       = new byte[16];
            byte[] cypherTxt = new byte[plaintext.Length];

            // Encrypt Data Into CypherTxt
            chaPoly.Encrypt(
                nonce,
                await ReadFileChunkFromOffset(plaintextFile, plaintext, offset),
                cypherTxt,
                tag
            );

            // Append cypherTxt to cypherTxtFile.
            await AppendFileChunk(cypherTxtFile, cypherTxt, offset, order);

            return new DecryptionKeyNote(nonce, tag, order);
        }


        private static List<byte[]> GetNonces(long dataLength) {

            List<byte[]> nonces = new();
            decimal count       = Convert.ToDecimal(dataLength / MaxValue);
            int nonceCount      = (int)Math.Ceiling(count);

            for (int i = 0; i <= nonceCount; i++) {
                bool added = false;
                do {
                    var nonce = GetNonce();

                    if (nonces.Contains(nonce) == false) {
                        nonces.Add(nonce);
                        added = true;
                    }
                } while (added == false);
            }

            return nonces;
        }


        private static byte[] GetNonce() {
            var nonce = new byte[12];
            RandomNumberGenerator.Create().GetBytes(nonce);
            return nonce;
        }

        #endregion Encryption Helpers

        #endregion Encryption

        #region Decryption
        public static async Task Decrypt(
            FileInfo keyFile,
            FileInfo cypherTxtFile,
            FileInfo plaintextFile
        ) {
            // Validate Input
            if (File.Exists(keyFile.FullName) && File.Exists(cypherTxtFile.FullName)) {

                DecryptionData data = DecryptionData.Deserialize(keyFile);

                // Validate Input
                if (cypherTxtFile.Length == 0) {
                    throw new ArgumentOutOfRangeException(
                        nameof(cypherTxtFile),
                        $"cypherTxtFile \"{cypherTxtFile.FullName}\" must have a length greater than 0."
                    );
                }

                await DecryptFile(data, cypherTxtFile, plaintextFile);

            } else {

                if (File.Exists(keyFile.FullName) == false) {
                    throw new ArgumentException($"KeyFile \"{keyFile.FullName}\" doesn't exist.", nameof(keyFile));
                }

                if (File.Exists(cypherTxtFile.FullName) == false) {
                    throw new ArgumentException($"CypherTxtFile \"{cypherTxtFile.FullName}\" doesn't exist.", nameof(cypherTxtFile));
                }
            }
        }

        #region Decryption Helpers

        private static async Task DecryptFile(
            DecryptionData keyFile,
            FileInfo       cypherTxtFile,
            FileInfo       plaintextFile
        ) {

            ChaCha20Poly1305        chaPoly        = new(keyFile.Key);
            List<DecryptionKeyNote> keyNoteList    = keyFile.KeyNoteList;
            long                    processedBytes = 0;
            int                     chunkCount     = 1;

            while (processedBytes < cypherTxtFile.Length) {

                byte[] plaintext = (chunkCount == keyNoteList.Count) ?
                                    new byte[cypherTxtFile.Length - processedBytes] :
                                    new byte[MaxValue];

                await DecryptFileChunk(
                    chaPoly,
                    keyNoteList[(chunkCount - 1)].Nonce,
                    keyNoteList[(chunkCount - 1)].Tag,
                    plaintext,
                    cypherTxtFile,
                    plaintextFile,
                    processedBytes,
                    chunkCount
                );

                processedBytes += plaintext.Length;
                chunkCount++;
            }
        }


        private static async Task DecryptFileChunk(
            ChaCha20Poly1305 chaPoly,
            byte[]           nonce,
            byte[]           tag,
            byte[]           cypherTxt,
            FileInfo         cypherTxtFile,
            FileInfo         plaintextFile,
            long             offset,
            int              order
        ) {
            var plainText = new byte[cypherTxt.Length];

            // Decrypt
            chaPoly.Decrypt(
                nonce,
                await ReadFileChunkFromOffset(cypherTxtFile, cypherTxt, offset),
                tag,
                plainText
            );

            // Append plaintext data to plaintextFile.
            await AppendFileChunk(plaintextFile, plainText, offset, order);
        }

        #endregion Decryption Helpers

        #endregion Decryption

        #region Helper Methods

        private static async Task AppendFileChunk(
            FileInfo outputFile,
            byte[]   data,
            long     offset,
            int      order
        ) {
            var fileMode = (order == 1) ? FileMode.Create : FileMode.Open;
            using FileStream outputFS = new(
                outputFile.FullName,
                fileMode,
                FileAccess.Write,
                FileShare.Read,
                10240,
                FileOptions.Asynchronous
            );
            outputFS.Seek(offset, SeekOrigin.Current);
            await outputFS.WriteAsync(data.AsMemory(0, data.Length));
        }

        private static async Task<byte[]> ReadFileChunkFromOffset(
            FileInfo inputFile,
            byte[]   data,
            long     offset
        ) {
            using FileStream inputFS = new(
                inputFile.FullName,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                10240,
                FileOptions.Asynchronous
            );
            // Read File from offset
            inputFS.Seek(offset, SeekOrigin.Begin);
            await inputFS.ReadAsync(data.AsMemory(0, data.Length));

            return data;
        }

        #endregion Helper Methods
    }
}
