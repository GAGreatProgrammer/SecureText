using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace SecureText.Classes
{
    public static class Decryptor
    {
        public static string AESDecryption(string text, string key)
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

                ICryptoTransform decryptor = aesAlgorithm.CreateDecryptor();

                byte[] cipher = Convert.FromBase64String(text);

                using (MemoryStream ms = new MemoryStream(cipher))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
        }

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
            string textData = null;
            string TripleDESData = null;
            string ROT13Data = null;
            string Base64Data = null;      

            TripleDESData = TripleDESDecryption(text, key);
            ROT13Data = ROT13Decryption(TripleDESData);
            Base64Data = Base64Decryption(ROT13Data);

            textData = Base64Data;

            return textData;
        }

        public static string TripleDES2RoundsDecryption(string text, string key)
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

            for (int i = 2; i >= 1; i--)
            {
                byte[] byteHash = hashMD5Provider.ComputeHash(Encoding.UTF8.GetBytes(match.Groups[i].Value));
                tripleDESCryptoService.Key = byteHash;
                tripleDESCryptoService.Mode = CipherMode.ECB;
                byte[] byteBuff = Convert.FromBase64String(textData);
                textData = Encoding.Unicode.GetString(tripleDESCryptoService.CreateDecryptor().TransformFinalBlock(byteBuff, 0, byteBuff.Length));
            }

            return textData;
        }

        public static string TripleDES4RoundsDecryption(string text, string key)
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

            for (int i = 4; i >= 1; i--)
            {
                byte[] byteHash = hashMD5Provider.ComputeHash(Encoding.UTF8.GetBytes(match.Groups[i].Value));
                tripleDESCryptoService.Key = byteHash;
                tripleDESCryptoService.Mode = CipherMode.ECB;
                byte[] byteBuff = Convert.FromBase64String(textData);
                textData = Encoding.Unicode.GetString(tripleDESCryptoService.CreateDecryptor().TransformFinalBlock(byteBuff, 0, byteBuff.Length));
            }

            return textData;
        }

        public static string RC4Decryption(string text, string key)
        {
            byte[] base64EncodedBytes = Convert.FromBase64String(text);
            string temp = Encoding.UTF8.GetString(base64EncodedBytes);

            byte[] _data = Encoding.UTF8.GetBytes(temp);
            byte[] _key = Encoding.UTF8.GetBytes(key);

            byte[] encrypted_data = Array.ConvertAll<string, byte>(temp.Split('-'), s => Convert.ToByte(s, 16));

            RC4_Algorithm rC4_Algorithm = new RC4_Algorithm();
            byte[] decrypted_data = rC4_Algorithm.RC4(encrypted_data, _key);
            string decrypted_phrase = Encoding.UTF8.GetString(decrypted_data);

            return decrypted_phrase;
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

        public static string Base64Decryption(string text)
        {
            byte[] base64EncodedBytes = Convert.FromBase64String(text);
            return Encoding.UTF8.GetString(base64EncodedBytes);
        }   
    }
}
