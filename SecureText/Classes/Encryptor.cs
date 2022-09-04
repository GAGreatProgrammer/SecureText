using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SecureText.Classes
{
    public static class Encryptor
    {
        public static string TripleDESEncryption(string text, string key)
        {
            TripleDESCryptoServiceProvider tripleDESCryptoService = new TripleDESCryptoServiceProvider();
            MD5CryptoServiceProvider hashMD5Provider = new MD5CryptoServiceProvider();

            byte[] byteHash = hashMD5Provider.ComputeHash(Encoding.UTF8.GetBytes(key));
            tripleDESCryptoService.Key = byteHash;
            tripleDESCryptoService.Mode = CipherMode.ECB;
            byte[] data = Encoding.Unicode.GetBytes(text);
            return Convert.ToBase64String(tripleDESCryptoService.CreateEncryptor().TransformFinalBlock(data, 0, data.Length));
        }

        public static string ExtendedTripleDESEncryption(string text, string key)
        {
            TripleDESCryptoServiceProvider tripleDESCryptoService = new TripleDESCryptoServiceProvider();
            MD5CryptoServiceProvider hashMD5Provider = new MD5CryptoServiceProvider();

            string textData = text;

            for (int i = 0; i < 3; i++)
            {
                byte[] byteHash = hashMD5Provider.ComputeHash(Encoding.UTF8.GetBytes(key));
                tripleDESCryptoService.Key = byteHash;
                tripleDESCryptoService.Mode = CipherMode.ECB;
                byte[] data = Encoding.Unicode.GetBytes(textData);
                textData = Convert.ToBase64String(tripleDESCryptoService.CreateEncryptor().TransformFinalBlock(data, 0, data.Length));
            }
            return textData;
        }

        public static string ROT13Encryption(string text)
        {
            StringBuilder result = new StringBuilder();
            Regex regex = new Regex("[A-Za-z]");
            foreach (char c in text)
            {
                if (regex.IsMatch(c.ToString()))
                {
                    int code = ((c & 223) - 52) % 26 + (c & 32) + 65;
                    result.Append((char)code);
                }
                else
                    result.Append(c);
            }
            return result.ToString();
        }

        public static string BinaryDecryption(string text)
        {
            StringBuilder sb = new StringBuilder();
            foreach (char c in text.ToCharArray())
                sb.Append(Convert.ToString(c, 2).PadLeft(8, '0'));
            return sb.ToString();
        }

        public static string BinaryTripleDESEncryption(string text, string key)
        {
            StringBuilder sb = new StringBuilder();
            string tempData = text;
            foreach (char c in tempData.ToCharArray())
                sb.Append(Convert.ToString(c, 2).PadLeft(8, '0'));
            tempData = sb.ToString();


            TripleDESCryptoServiceProvider tripleDESCryptoService = new TripleDESCryptoServiceProvider();
            MD5CryptoServiceProvider hashMD5Provider = new MD5CryptoServiceProvider();

            byte[] byteHash = hashMD5Provider.ComputeHash(Encoding.UTF8.GetBytes(key));
            tripleDESCryptoService.Key = byteHash;
            tripleDESCryptoService.Mode = CipherMode.ECB;
            byte[] data = Encoding.Unicode.GetBytes(tempData);
            return Convert.ToBase64String(tripleDESCryptoService.CreateEncryptor().TransformFinalBlock(data, 0, data.Length));
        }

    }
}
