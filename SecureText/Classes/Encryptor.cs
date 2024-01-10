using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace SecureText.Classes
{
    public static class Encryptor
    {
        public static string AESEncryption(string text, string key)
        {
            string pattern = @"Key\(([^)]+)\) : IV\(([^)]+)\)";
            string AES_Key = null;
            string AES_IV = null;

            Match match = Regex.Match(key, pattern);

            if (match.Success)
            {
                AES_Key = match.Groups[1].Value;
                AES_IV = match.Groups[2].Value;
            }
            else
            {
                MessageBox.Show("Invalid password pattern!", "Exception", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

            using (Aes aesAlgorithm = Aes.Create())
            {
                aesAlgorithm.Key = Convert.FromBase64String(AES_Key);
                aesAlgorithm.IV = Convert.FromBase64String(AES_IV);

                ICryptoTransform encryptor = aesAlgorithm.CreateEncryptor();

                byte[] encryptedData;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(text);
                        }
                        encryptedData = ms.ToArray();
                    }
                }
                return Convert.ToBase64String(encryptedData);
            }
        }

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
            string textData = null;
            string Base64Data = null;
            string ROT13Data = null;

            Base64Data = Base64Encryption(text);
            ROT13Data = ROT13Encryption(Base64Data);
            textData = TripleDESEncryption(ROT13Data, key);

            return textData;
        }

        public static string TripleDES2RoundsEncryption(string text, string key)
        {
            TripleDESCryptoServiceProvider tripleDESCryptoService = new TripleDESCryptoServiceProvider();
            MD5CryptoServiceProvider hashMD5Provider = new MD5CryptoServiceProvider();

            string pattern = @"Key1\(([^)]+)\) : Key2\(([^)]+)\)";
            string textData = text;
            string key1 = null;
            string key2 = null;

            Match match = Regex.Match(key, pattern);
            if (match.Success)
            {
                key1 = match.Groups[1].Value;
                key2 = match.Groups[2].Value;
            }

            for (int i = 1; i <= 2; i++)
            {
                byte[] byteHash = hashMD5Provider.ComputeHash(Encoding.UTF8.GetBytes(match.Groups[i].Value));
                tripleDESCryptoService.Key = byteHash;
                tripleDESCryptoService.Mode = CipherMode.ECB;
                byte[] data = Encoding.Unicode.GetBytes(textData);
                textData = Convert.ToBase64String(tripleDESCryptoService.CreateEncryptor().TransformFinalBlock(data, 0, data.Length));
            }

            return textData;
        }

        public static string TripleDES4RoundsEncryption(string text, string key)
        {
            TripleDESCryptoServiceProvider tripleDESCryptoService = new TripleDESCryptoServiceProvider();
            MD5CryptoServiceProvider hashMD5Provider = new MD5CryptoServiceProvider();

            string pattern = @"Key1\(([^)]+)\) : Key2\(([^)]+)\) : Key3\(([^)]+)\) : Key4\(([^)]+)\)";
            string textData = text;

            string key1 = null;
            string key2 = null;
            string key3 = null;
            string key4 = null;

            Match match = Regex.Match(key, pattern);
            if (match.Success)
            {
                key1 = match.Groups[1].Value;
                key2 = match.Groups[2].Value;
                key3 = match.Groups[3].Value;
                key4 = match.Groups[4].Value;
            }

            for (int i = 1; i <= 4; i++)
            {
                byte[] byteHash = hashMD5Provider.ComputeHash(Encoding.UTF8.GetBytes(match.Groups[i].Value));
                tripleDESCryptoService.Key = byteHash;
                tripleDESCryptoService.Mode = CipherMode.ECB;
                byte[] data = Encoding.Unicode.GetBytes(textData);
                textData = Convert.ToBase64String(tripleDESCryptoService.CreateEncryptor().TransformFinalBlock(data, 0, data.Length));
            }

            return textData;
        }

        public static string RC4Encryption(string text, string key)
        {
            byte[] _data = Encoding.UTF8.GetBytes(text);
            byte[] _key = Encoding.UTF8.GetBytes(key);

            RC4_Algorithm rC4_Algorithm = new RC4_Algorithm();
            byte[] encrypted_data = rC4_Algorithm.RC4(_data, _key);

            byte[] plainTextBytes = Encoding.UTF8.GetBytes(BitConverter.ToString(encrypted_data));
            return Convert.ToBase64String(plainTextBytes);
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

        public static string Base64Encryption(string text)
        {
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(text);
            return Convert.ToBase64String(plainTextBytes);
        }
    }
}
