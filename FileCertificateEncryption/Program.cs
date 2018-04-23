using System;

namespace FileCertificateEncryption
{
    class Program
    {
        private const string File = @"";
        private const string CertPath = @"";
        private const string CertPassword = "";

        static void Main(string[] args)
        {
            Encrypter.Encrypt(File, CertPath, CertPassword).Wait();
            Console.ReadKey();
            Decrypter.Decrypt(File, CertPath, CertPassword).Wait();
        }
    }
}
