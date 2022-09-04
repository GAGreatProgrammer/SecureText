using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SecureText.Classes
{
    public static class Decryptor
    {
        public static string TripleDESDecryption(string text, string key)
        {
            TripleDESCryptoServiceProvider tripleDESCryptoService = new TripleDESCryptoServiceProvider();
            MD5CryptoServiceProvider hashMD5Provider = new MD5CryptoServiceProvider();

            byte[] byteHash = hashMD5Provider.ComputeHash(Encoding.UTF8.GetBytes(key));
            tripleDESCryptoService.Key = byteHash;
            tripleDESCryptoService.Mode = CipherMode.ECB;
            byte[] byteBuff = Convert.FromBase64String(text);
            return Encoding.Unicode.GetString(tripleDESCryptoService.CreateDecryptor().TransformFinalBlock(byteBuff, 0, byteBuff.Length));
        }

        public static string ExtendedTripleDESDecryption(string text, string key)
        {
            TripleDESCryptoServiceProvider tripleDESCryptoService = new TripleDESCryptoServiceProvider();
            MD5CryptoServiceProvider hashMD5Provider = new MD5CryptoServiceProvider();

            string textData = text;

            for (int i = 0; i < 3; i++)
            {
                byte[] byteHash = hashMD5Provider.ComputeHash(Encoding.UTF8.GetBytes(key));
                tripleDESCryptoService.Key = byteHash;
                tripleDESCryptoService.Mode = CipherMode.ECB;
                byte[] byteBuff = Convert.FromBase64String(textData);
                textData = Encoding.Unicode.GetString(tripleDESCryptoService.CreateDecryptor().TransformFinalBlock(byteBuff, 0, byteBuff.Length));
            }

            return textData;
        }

        public static string ROT13Decryption(string text)
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
            List<Byte> byteList = new List<Byte>();

            for (int i = 0; i < text.Length; i += 8)
            {
                byteList.Add(Convert.ToByte(text.Substring(i, 8), 2));
            }
            return Encoding.ASCII.GetString(byteList.ToArray());
        }

        public static string BinaryTripleDESEncryption(string text, string key)
        {
            TripleDESCryptoServiceProvider tripleDESCryptoService = new TripleDESCryptoServiceProvider();
            MD5CryptoServiceProvider hashMD5Provider = new MD5CryptoServiceProvider();

            string tempData = null;

            byte[] byteHash = hashMD5Provider.ComputeHash(Encoding.UTF8.GetBytes(key));
            tripleDESCryptoService.Key = byteHash;
            tripleDESCryptoService.Mode = CipherMode.ECB;
            byte[] byteBuff = Convert.FromBase64String(text);
            tempData = Encoding.Unicode.GetString(tripleDESCryptoService.CreateDecryptor().TransformFinalBlock(byteBuff, 0, byteBuff.Length));


            List<Byte> byteList = new List<Byte>();
            for (int i = 0; i < tempData.Length; i += 8)
            {
                byteList.Add(Convert.ToByte(tempData.Substring(i, 8), 2));
            }
            tempData = Encoding.ASCII.GetString(byteList.ToArray());
            return tempData;
        }

    }
}
