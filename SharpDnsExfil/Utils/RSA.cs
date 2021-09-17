using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SharpDnsExfil.Utils
{
    class RSA
    {

            /// <summary>
            /// Create a public and private key.
            ///
            /// The RSACryptoServiceProvider supports key sizes from 384
            /// bits to 16384 bits in increments of 8 bits if you have the
            /// Microsoft Enhanced Cryptographic Provider installed. It
            /// supports key sizes from 384 bits to 512 bits in increments
            /// of 8 bits if you have the Microsoft Base Cryptographic
            /// Provider installed.
            /// </summary>
            /// <param name="publicKey">The created public key.</param>
            /// <param name="privateKey">The created private key.</param>
            /// <param name="keySize">Size of keys.</param>
        public void CreateKeys(out string publicKey, out string privateKey, int keySize = 2048)
        {
            publicKey = null;
            privateKey = null;

            var csp = new CspParameters
            {
                ProviderType = 1,
                Flags = CspProviderFlags.UseArchivableKey,
                KeyNumber = (int)KeyNumber.Exchange
            };

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySize, csp);

            publicKey = rsa.ToXmlString(false);
            privateKey = rsa.ToXmlString(true);

            rsa.PersistKeyInCsp = false;
        }

        /// <summary>
        /// Encrypt data using a public key.
        /// </summary>
        /// <param name="bytes">Bytes to encrypt.</param>
        /// <param name="publicKey">Public key to use.</param>
        /// <returns>Encrypted data.</returns>
        public byte[] Encrypt(byte[] bytes, string publicKey)
        {
            var csp = new CspParameters
            {
                ProviderType = 1
            };

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csp);

            rsa.FromXmlString(publicKey);
            var data = rsa.Encrypt(bytes, true); //changed to true because i use PKCS_OAEP //https://stackoverflow.com/questions/23615181/c-sharp-if-i-have-private-key-how-do-i-decrypt

            rsa.PersistKeyInCsp = false;

            return data;
        }

        /// <summary>
        /// Encrypt data using a public key.
        /// </summary>
        /// <param name="input">Data to encrypt.</param>
        /// <param name="publicKey">Public key to use.</param>
        /// <returns>Encrypted data.</returns>
        public string Encrypt(string input, string publicKey)
        {
            if (input == null)
            {
                throw new Exception("Input cannot be null");
            }

            return Convert.ToBase64String(
                Encrypt(
                    Encoding.UTF8.GetBytes(input),
                    publicKey));
        }

        /// <summary>
        /// Decrypt data using a private key.
        /// </summary>
        /// <param name="bytes">Bytes to decrypt.</param>
        /// <param name="privateKey">Private key to use.</param>
        /// <returns>Decrypted data.</returns>
        public byte[] Decrypt(byte[] bytes, string privateKey)
        {
            var csp = new CspParameters
            {
                ProviderType = 1
            };

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csp);

            rsa.FromXmlString(privateKey);
            var data = rsa.Decrypt(bytes, true);

            rsa.PersistKeyInCsp = false;

            return data;
        }

        /// <summary>
        /// Decrypt data using a private key.
        /// </summary>
        /// <param name="input">Base64 data to decrypt.</param>
        /// <param name="privateKey">Private key to use.</param>
        /// <returns>Decrypted data.</returns>
        public string Decrypt(string input, string privateKey)
        {
            if (input == null)
            {
                throw new Exception("Input cannot be null");
            }

            return Encoding.UTF8.GetString(
                Decrypt(
                    Convert.FromBase64String(input),
                    privateKey));
        }
    }
}
