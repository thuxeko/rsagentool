using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using PaygateRSALib;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace RsaGen
{
    class Program
    {
        static void Main(string[] args)
        {
            int key_size = 2048;
            #region Gen RSA
            Console.WriteLine("Gen Key");
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(key_size))
            {
                string publicKey = RSAKeysToPEM.GetPublicPEM(rsa);
                string privateKey = RSAKeysToPEM.GetPrivatePEM(rsa);
                File.WriteAllText("private_key.pem", privateKey);
                File.WriteAllText("public_key.pem", publicKey);

                var rsa_pk = CreateRsaFromPem(privateKey, true);
                File.WriteAllText("private_key_rsa.txt", rsa_pk);

                var rsa_pb = CreateRsaFromPem(privateKey, false);
                File.WriteAllText("public_key_rsa.txt", rsa_pb);
            }
            #endregion

            Console.WriteLine("Done");
            Console.ReadLine();
        }

        #region RSA Base
        public static string CreateRsaFromPem(string pem, bool pkb)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pem.ToCharArray());

            return rsa.ToXmlString(pkb);
        }
        #endregion

        #region Encrypt/Decrypt
        public static string Encrypt(string textToEncrypt, string publicKeyString, int num_bits)
        {
            var bytesToEncrypt = Encoding.UTF8.GetBytes(textToEncrypt);

            using (var rsa = new RSACryptoServiceProvider(num_bits))
            {
                try
                {
                    rsa.FromXmlString(publicKeyString.ToString());
                    var encryptedData = rsa.Encrypt(bytesToEncrypt, true);
                    var base64Encrypted = Convert.ToBase64String(encryptedData);
                    return base64Encrypted;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        public static string Decrypt(string textToDecrypt, string privateKeyString, int num_bits)
        {
            var bytesToDescrypt = Encoding.UTF8.GetBytes(textToDecrypt);

            using (var rsa = new RSACryptoServiceProvider(num_bits))
            {
                try
                {

                    // server decrypting data with private key                    
                    rsa.FromXmlString(privateKeyString);

                    var resultBytes = Convert.FromBase64String(textToDecrypt);
                    var decryptedBytes = rsa.Decrypt(resultBytes, true);
                    var decryptedData = Encoding.UTF8.GetString(decryptedBytes);
                    return decryptedData.ToString();
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }
        #endregion
    }
}
