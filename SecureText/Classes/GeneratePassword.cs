using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace SecureText.Classes
{
    public static class GeneratePassword
    {
        const string Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const string Lowercase = "abcdefghijklmnopqrstuvwxyz";
        const string Numbers = "1234567890";
        const string Symbols = @"~!@#$%^&*():;[]{}<>,.?/\|";


        public static string Generate()
        {
            try
            {
                char[] password = new char[25];
                string charSet = "";


                Random random = new Random();

                charSet += Uppercase;

                charSet += Lowercase;

                charSet += Numbers;

                charSet += Symbols;

                for (int i = 0; i < 25; i++)
                    password[i] = charSet[random.Next(charSet.Length - 1)];

                return string.Join(null, password);
            }
            catch
            {
                return "Something went wrong!";
            }
        }

        public static string AESPassword()
        {
            string Password = null;

            using (Aes aesAlgorithm = Aes.Create())
            {
                aesAlgorithm.KeySize = 256;
                aesAlgorithm.GenerateKey();
                aesAlgorithm.GenerateIV();
                string keyBase64 = Convert.ToBase64String(aesAlgorithm.Key);
                string vectorBase64 = Convert.ToBase64String(aesAlgorithm.IV);

                Password = $"Key({keyBase64}) : IV({vectorBase64})";
            }
            return Password;
        }

        public static string TwoPasswords()
        {
            try
            {
                var passList = new List<string>();
                string pw = null;

                Random random = new Random();

                for (int p = 0; p < 2; p++)
                {
                    char[] password = new char[25];
                    string charSet = "";

                    charSet += Uppercase;

                    charSet += Lowercase;

                    charSet += Numbers;

                    charSet += Symbols;

                    for (int i = 0; i < 25; i++)
                        password[i] = charSet[random.Next(charSet.Length - 1)];

                    passList.Add(string.Join(null, password));
                }

                foreach (var pass in passList)
                {
                    pw = $"Key1({passList[0]}) : Key2({passList[1]})";
                }  
                return pw;
            }
            catch
            {
                return "Something went wrong!";
            }
        }

        public static string FourPasswords()
        {
            try
            {
                var passList = new List<string>();
                string pw = null;

                Random random = new Random();

                for (int p = 0; p < 4; p++)
                {
                    char[] password = new char[25];
                    string charSet = "";

                    charSet += Uppercase;

                    charSet += Lowercase;

                    charSet += Numbers;

                    charSet += Symbols;

                    for (int i = 0; i < 25; i++)
                        password[i] = charSet[random.Next(charSet.Length - 1)];

                    passList.Add(string.Join(null, password));
                }

                foreach (var pass in passList)
                {
                    pw = $"Key1({passList[0]}) : Key2({passList[1]}) : Key3({passList[2]}) : Key4({passList[3]})";
                }
                return pw;
            }
            catch
            {
                return "Something went wrong!";
            }
        }
    }
}
