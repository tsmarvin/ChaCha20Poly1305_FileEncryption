using System.Text.Json;
using System.Text.Json.Serialization;

namespace FileEncryption.Types {
    internal class DecryptionKeyNote {
        [JsonIgnore]
        public byte[] Nonce { get; set; }
        [JsonIgnore]
        public byte[] Tag { get; set; }

        [JsonInclude]
        public int Order { get; set; }

        // Include Base64 Formatted String Properties
        [JsonInclude]
        [JsonPropertyName("Nonce")]
        public string nonce { get; private set; }
        [JsonInclude]
        [JsonPropertyName("Tag")]
        public string tag { get; private set; }

        public DecryptionKeyNote(byte[] nonce, byte[] tag, int order) {
            Nonce      = nonce;
            Tag        = tag;
            Order      = order;
            this.nonce = Convert.ToBase64String(nonce, 0, nonce.Length);
            this.tag   = Convert.ToBase64String(tag, 0, tag.Length);
        }

        [JsonConstructor]
        public DecryptionKeyNote(string nonce, string tag, int order) {
            Nonce      = Convert.FromBase64String(nonce);
            Tag        = Convert.FromBase64String(tag);
            Order      = order;
            this.nonce = nonce;
            this.tag   = tag;
        }

        public override string ToString() {
            return JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
        }
    }
}
