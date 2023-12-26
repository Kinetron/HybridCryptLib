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
using HybridCryptLib.Models;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Tls;
using System.IO;

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

			Assert.IsTrue(text.SequenceEqual(decryptData));
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

		/// <summary>
		/// Тест кодирования декодирования пользовательских данных.
		/// </summary>
		[Test]
		public void ProtectData()
		{
			UserInfo info = new UserInfo()
			{
				Name = "Дудкин Иван Басович",
				Phone = "+12345678988",
				Email = "somemail@mail"
			};

			CryptUserInfo cryptUserInfo = new CryptUserInfo();
			byte[] cryptData = cryptUserInfo.Crypt(info, "TestData\\cert.crt");

			UserInfo decodeInfo = cryptUserInfo.DeCrypt(cryptData, _privateKeyPath, _privateKeyPassword);

			Assert.AreEqual(info.Name, decodeInfo.Name);
		}

		/// <summary>
		/// Создание сертификата и загрузка открытого ключа из него.
		/// </summary>
		[Test]
		public void CertCreate()
		{
			СommonCrypt сommonCrypt = new СommonCrypt();
			AsymmetricCipherKeyPair pair = (AsymmetricCipherKeyPair)сommonCrypt.LoadPem(_privateKeyPath, _privateKeyPassword);
	
			DateTime certBegin = DateTime.Now; //Дата начала действия сертификата.
			DateTime certEnd = certBegin.AddYears(10);

			string certContent = сommonCrypt.GenRootCert(pair,
				"HybridCryptMain", certBegin, certEnd);

			File.WriteAllText("cert.crt", certContent);
			
			using (var file = File.OpenRead("cert.crt"))
			{
				X509CertificateParser parser = new X509CertificateParser();
				var certificate = parser.ReadCertificate(file);
				AsymmetricKeyParameter pubKey =  certificate.GetPublicKey();
                Assert.IsNotNull(pubKey);  				
			}
		}
	}
}
