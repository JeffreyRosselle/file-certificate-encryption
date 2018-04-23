using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace FileCertificateEncryption
{
    public static class Decrypter
    {
        public static async Task Decrypt(string filePath, string certName, string password)
        {
            var file = (await File.ReadAllBytesAsync(filePath)).ToList();
            var encryptedKey = new Collection<byte>();
            //Checking the length so we know how much we bytes we need to take from the file.
            var encryptLength = Encrypter.EncryptKey(Encoding.UTF8.GetBytes("string"), certName, password).Length;
            for (var i = 0; i < encryptLength; i++)
                encryptedKey.Add(file[i]);
            file.RemoveRange(0, encryptLength);

            var decryptedKey = DecryptKey(encryptedKey.ToArray(), certName, password);

            using (var managed = new AesManaged())
            {
                Aes aesKey = Aes.Create();
                aesKey.Key = decryptedKey;
                byte[] ivKey = new byte[aesKey.IV.Length];
                Array.Copy(aesKey.Key, ivKey, aesKey.IV.Length);
                aesKey.IV = ivKey;
                var decryptor = aesKey.CreateDecryptor();

                using (var cryptFileStream = new FileStream(filePath, FileMode.Truncate))
                using (var decryptStream = new CryptoStream(cryptFileStream, decryptor, CryptoStreamMode.Write))
                using (var outputFileStream = new MemoryStream(file.ToArray()))
                    await outputFileStream.CopyToAsync(decryptStream);
            }
        }

        private static byte[] DecryptKey(byte[] keyBytes, string certName, string password)
        {
            var cert = new X509Certificate2(certName, password);
            var privateKey = cert.GetRSAPrivateKey();
            return privateKey.Decrypt(keyBytes, RSAEncryptionPadding.OaepSHA512);
        }
    }
}
