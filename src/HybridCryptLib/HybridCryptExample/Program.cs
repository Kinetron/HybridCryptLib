﻿using HybridCryptLib.Services;
using Org.BouncyCastle.Crypto;
using System.Text;

namespace HybridCryptExample
{
	internal class Program
	{
		private static readonly string _privateKeyPath = "private_key";
		private static readonly string _privateKeyPassword = "1237845Ax15";

		static void Main(string[] args)
		{
			Console.WriteLine("Hello, World!");

			СommonCrypt сommonCrypt = new СommonCrypt();
			if (!сommonCrypt.CheckKeyPassword(_privateKeyPath, _privateKeyPassword))
			{
				Console.WriteLine(сommonCrypt.LastError);
				return;
			}
			
			AsymmetricCipherKeyPair pair = (AsymmetricCipherKeyPair)сommonCrypt.LoadPem($"private_key", _privateKeyPassword);
			//X509Certificate cert = (X509Certificate)сommonCrypt.LoadPem($"private_key", _privateKeyPassword);

			DateTime certBegin = DateTime.Now; //Дата начала действия сертификата.
			DateTime certEnd = certBegin.AddYears(10);

			string certContent = сommonCrypt.GenCert(pair,
				"HybridCryptMain", certBegin, certEnd);

			File.WriteAllText($"cert.crt", certContent);

			//Генерируем ключ шифрования ассиметричной системы.
			byte[] aesKey = сommonCrypt.GenerateRandom(32);
			byte[] iv = сommonCrypt.GenerateRandom(32);

			string aesStrKey = Convert.ToBase64String(aesKey);

			string encryptData = сommonCrypt.EncryptRsa("private_key", "123", _privateKeyPassword);
			if(encryptData == null)
			{
				Console.WriteLine(сommonCrypt.LastError);
				return;
			}

			string test = "fdhjsklahffn,smnfsdlfsadjf;lklk;";
			сommonCrypt.EncryptAes(Encoding.UTF8.GetBytes(test), aesKey, iv);

			//Encoding.UTF8.GetBytes(str)
		}
	}
}
