using HybridCryptLib.Services;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.X509;
using static System.Runtime.InteropServices.JavaScript.JSType;
using System.Security.Cryptography.X509Certificates;

namespace HybridCryptLib.Tests
{
	public class LibTests
	{
		/// <summary>
		/// Путь к файлу содержащий открытый и закрытый ключ.
		/// </summary>
		private readonly string _privateKeyPath = "TestData\\pem_key";
		private  readonly string _privateKeyPassword = "1237845Ax15";

		/// <summary>
		/// Шифрование/расшифровка строки.
		/// </summary>
		[Test]
		public void AesEncriptDecriptTest()
		{
			СommonCrypt сommonCrypt = new СommonCrypt();

			//Генерируем ключ шифрования для блочного шифра.
			byte[] aesKey = сommonCrypt.GenerateRandom(32);
			byte[] iv = сommonCrypt.GenerateRandom(16); //Начальный вектор.

			string strToCrypt = @"With our tools, you can build visually while the apps take care of the heavy code 
			lifting for you. Unleash your creativity while building the perfect digital environment for your content.";
			
			byte[] cryptResult = сommonCrypt.EncryptAes(Encoding.UTF8.GetBytes(strToCrypt), aesKey, iv);

			byte[] decryptResult = сommonCrypt.DecryptAes(cryptResult, aesKey, iv);

			string decryptStr = Encoding.UTF8.GetString(decryptResult);

			//Строка дополняется символами \0 с 192 до 208.
			decryptStr = decryptStr.Substring(0, strToCrypt.Length);
			Assert.AreEqual(decryptStr, strToCrypt);
		}

		/// <summary>
		/// Тест метода проверки пароля для закрытого ключа.
		/// </summary>
		[Test]
		public void CheckPasswordToRsaPemKey()
		{
			СommonCrypt сommonCrypt = new СommonCrypt();
			Assert.IsTrue(сommonCrypt.CheckKeyPassword(_privateKeyPath, _privateKeyPassword));

			string badPassword = _privateKeyPassword + "bad";
			Assert.IsFalse(сommonCrypt.CheckKeyPassword(_privateKeyPath, badPassword));
		}

		/// <summary>
		/// Шифрует закрытым ключем, расшифровывает открытым.
		/// Фактически урезанный алгоритм подписи(нет хэш)
		/// </summary>
		[Test]
		public void RsaPrivateKeyCrypt()
		{
			СommonCrypt сommonCrypt = new СommonCrypt();
			byte[] text = Encoding.ASCII.GetBytes("How does RSA work?");

			//Шифруем закрытым ключем.
			byte[] cryptData = сommonCrypt.EncryptRsaUsePrivateKey(_privateKeyPath, text, _privateKeyPassword);
			Assert.IsNotNull(cryptData);

			AsymmetricCipherKeyPair pair = сommonCrypt.LoadPem(_privateKeyPath, _privateKeyPassword) as AsymmetricCipherKeyPair;
			Assert.IsNotNull(pair);

			//Расшифровываем открытым.
			byte[] decryptData = сommonCrypt.DecryptRsaUsePublicKey(cryptData, pair.Public);

			for (int i = 0; i < decryptData.Length; i++)
			{
				Assert.AreEqual(text[i], decryptData[i]);
			}
		}

		/// <summary>
		/// Шифрование закрытым ключем. Аналог алгоритма гибридного шифрования.
		/// </summary>
		[Test]
		public void RsaPublicKeyCrypt()
		{
			СommonCrypt сommonCrypt = new СommonCrypt();
			byte[] text = Encoding.ASCII.GetBytes("Session key is random number  ");

			AsymmetricCipherKeyPair pair = сommonCrypt.LoadPem(_privateKeyPath, _privateKeyPassword) as AsymmetricCipherKeyPair;
			Assert.IsNotNull(pair);
			byte[] cryptText = сommonCrypt.EncryptRsaUsePublicKey(text, pair.Public);
			Assert.IsNotNull(cryptText);

			byte[] decryptText = сommonCrypt.DecryptRsaUsePrivateKey(cryptText, pair.Private);
			Assert.IsNotNull(decryptText);

			string decryptStr = Encoding.UTF8.GetString(decryptText);
			Assert.AreEqual(text, decryptStr);
		}
	}
}
