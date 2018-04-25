using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace FileCertificateEncryption
{
    public static class Encrypter
    {
        public static async Task Encrypt(string filePath, string certName, string password)
        {
            //I'm using AES encryption to create my key.
            Aes aesKey = Aes.Create();
            aesKey.GenerateKey();
            byte[] ivKey = new byte[aesKey.IV.Length];
            Array.Copy(aesKey.Key, ivKey, aesKey.IV.Length);
            aesKey.IV = ivKey;
            var encryptor = aesKey.CreateEncryptor();
            var encryptedKey = EncryptKey(aesKey.Key, certName, password);

            //Copy the file to memory so we can override the source with it's encrypted version.
            var file = await File.ReadAllBytesAsync(filePath);

            //I use trancate mode, so the file opens up and is empty.
            using (var outputStream = new FileStream(filePath, FileMode.Truncate))
            {
                //Add encryptedKey to start of file.
                await outputStream.WriteAsync(encryptedKey, 0, encryptedKey.Length);
                using (var encryptStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write))
                using (var inputStream = new MemoryStream(file))
                    await inputStream.CopyToAsync(encryptStream);
            }
        }

        public static byte[] EncryptKey(byte[] key, string certName, string password)
        {
            var cert = new X509Certificate2(certName, password);
            var publicKey = cert.GetRSAPublicKey();
            //Encrypt the key with certificate
            return publicKey.Encrypt(key, RSAEncryptionPadding.OaepSHA512);
        }
    }
}
