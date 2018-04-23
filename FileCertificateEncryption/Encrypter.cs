using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace FileCertificateEncryption
{
    public static class Encrypter
    {
        public static async Task Encrypt(string filePath, string certName, string password)
        {
            Aes aesKey = Aes.Create();
            aesKey.GenerateKey();
            byte[] ivKey = new byte[aesKey.IV.Length];
            Array.Copy(aesKey.Key, ivKey, aesKey.IV.Length);
            aesKey.IV = ivKey;
            var encryptor = aesKey.CreateEncryptor();
            var encryptedKey = EncryptKey(aesKey.Key, certName, password);
            var file = await File.ReadAllBytesAsync(filePath);

            using (var outputStream = new FileStream(filePath, FileMode.Truncate))
            {
                //Add encryptedKey to start of file.
                await outputStream.WriteAsync(encryptedKey, 0, encryptedKey.Length);
                using (var encryptStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write))
                using (var inputFileStream = new MemoryStream(file))
                    await inputFileStream.CopyToAsync(encryptStream);
            }
        }

        public static byte[] EncryptKey(byte[] key, string certName, string password)
        {
            var cert = new X509Certificate2(certName, password);
            var publicKey = cert.GetRSAPublicKey();
            return publicKey.Encrypt(key, RSAEncryptionPadding.OaepSHA512);
        }
    }
}
