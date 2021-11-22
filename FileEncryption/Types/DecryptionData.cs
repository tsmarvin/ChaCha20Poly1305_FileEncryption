using System.Text.Json;
using System.Text.Json.Serialization;

namespace FileEncryption.Types {
    internal class DecryptionData {
        // Ignore complex object, Include base64 formatted string properties.
        [JsonIgnore]
        public byte[] Key { get; private set; }
        [JsonInclude]
        [JsonPropertyName("Key")]
        public readonly string key;

        // DecryptionKeyNote.ToString() formats it's properties as base64 strings.
        [JsonInclude]
        public List<DecryptionKeyNote> KeyNoteList { get; private set; } = new();

        public DecryptionData(byte[] _key, List<DecryptionKeyNote> nonceTagPair) {
            Key         = _key;
            key         = Convert.ToBase64String(_key, 0, _key.Length);
            KeyNoteList = nonceTagPair;
            ValidateLength();
        }

        [JsonConstructor]
        public DecryptionData(string key, List<DecryptionKeyNote> nonceTagPair) {
            Key      = Convert.FromBase64String(key);
            this.key = key;
            KeyNoteList.AddRange(nonceTagPair.ToArray());
            ValidateLength();
        }

        private void ValidateLength() {
            if (Key.Length != 32) {
                throw new ArgumentOutOfRangeException(
                    nameof(Key),
                    $"Key should be 32 bytes (256 bits). Current Length={Key.Length}"
                );
            }

            var ntpCount = 0;
            foreach (DecryptionKeyNote ntp in KeyNoteList) {
                // Check Tag Size
                if (ntp.Tag.Length != 16) {
                    throw new ArgumentOutOfRangeException(
                        "KeyNoteList.Tag",
                        $"KeyNoteList[{ntpCount}].Tag should be 16 bytes (128 bits). " +
                        $"Current Length: {ntp.Tag.Length}"
                    );
                }

                // Check Nonce Size
                if (ntp.Nonce.Length != 12) {
                    throw new ArgumentOutOfRangeException(
                        "KeyNoteList.Nonce",
                        $"KeyNoteList[{ntpCount}].Nonce should be 12 bytes (96 bits). " +
                        $"Current Length: {ntp.Nonce.Length}"
                    );
                }
                ntpCount++;
            }
        }

        public override string ToString() {
            return JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
        }

        public static DecryptionData Deserialize(FileInfo keyFile) {
            if (File.Exists(keyFile.FullName)) {
                // Read KeyFile
                var json = File.ReadAllText(keyFile.FullName);

                // Parse JsonDocument
                using JsonDocument document = JsonDocument.Parse(json);
                JsonElement root = document.RootElement;

                // Interpret Key
                string? _key = null;
                if (root.TryGetProperty(nameof(Key), out JsonElement key)) {
                    _key = key.GetString();
                }

                // Interpret KeyNoteList's
                List<DecryptionKeyNote> decryptionPairs = new();
                if (root.TryGetProperty(nameof(KeyNoteList), out JsonElement nonceTagPair)) {

                    var ntpCount = 0;
                    foreach (var ntp in nonceTagPair.EnumerateArray()) {
                        string? _nonce = null;
                        string? _tag   = null;
                        int? _order    = null;

                        if (ntp.TryGetProperty("Nonce", out JsonElement nonce)) { _nonce = nonce.GetString(); }

                        if (ntp.TryGetProperty("Tag", out JsonElement Tag))     { _tag   = Tag.GetString(); }

                        if (ntp.TryGetProperty("Order", out JsonElement Order)) { _order = Order.GetInt32(); }

                        if (
                            _nonce != null &&
                            _tag   != null &&
                            _order != null
                        ) {
                            decryptionPairs.Add(new(_nonce, _tag, (int)_order));
                        } else {
                            throw new ArgumentOutOfRangeException(
                                nameof(keyFile),
                                $"KeyNoteList[{ntpCount}] Is Invalid. Invalid Keyfile."
                            );
                        }
                        ntpCount++;
                    }
                }

                return (_key != null && decryptionPairs.Count > 0) ?
                    new DecryptionData(_key, decryptionPairs) :
                    throw new ArgumentOutOfRangeException(nameof(keyFile), "Invalid Keyfile.");

            } else {
                throw new ArgumentException("KeyFile doesn't exist.", nameof(keyFile));
            }
        }
    }
}
