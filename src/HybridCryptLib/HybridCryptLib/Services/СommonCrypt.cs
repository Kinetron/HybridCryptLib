using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using static System.Runtime.InteropServices.JavaScript.JSType;
using Org.BouncyCastle.Crypto.Digests;

namespace HybridCryptLib.Services
{
	/// <summary>
	/// Общие функции для работы с криптографией.
	/// </summary>
	public class СommonCrypt
	{
		public string LastError { get; set; }

		public bool CheckKeyPassword(string pathToPrivateKey, string password)
		{
			if (!File.Exists(pathToPrivateKey))
			{
				LastError = "Закрытый ключ по указанному пути не найден";
			}
			try
			{
				var pem = LoadPem(pathToPrivateKey, password);
				if (pem == null)
				{
					LastError = "Не верный формат файла.";
					return false;
				}

				return true;
			}
			catch (Exception ex)
			{
				LastError = ex.Message;
				return false;
			}
		}

		/// <summary>
		/// Загрузка pem файла.
		/// </summary>
		/// <param name="path"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		public object LoadPem(string path, string password)
		{
			TextReader readerPrivateKey = new StringReader(File.ReadAllText(path));
			PemReader pemReaderPrivateKey;
			if (string.IsNullOrEmpty(password))
			{
				pemReaderPrivateKey = new PemReader(readerPrivateKey);
			}
			else
			{
				pemReaderPrivateKey = new PemReader(readerPrivateKey, new PasswordFinder(password));
			}

			return pemReaderPrivateKey.ReadObject();
		}

		/// <summary>
		/// Создает само подписной сертификат CA.
		/// </summary>
		/// <param name="pair"></param>
		/// <param name="issuer"></param>
		/// <param name="dateBegin"></param>
		/// <param name="dateEnd"></param>
		/// <returns></returns>
		public string GenRootCert(AsymmetricCipherKeyPair pair,
			string issuer, DateTime dateBegin, DateTime dateEnd)
		{
			if (string.IsNullOrEmpty(issuer))
			{
				LastError = "Не указано кем и кому выдан сертификат";
				return null;
			}

			try
			{
				X509Name IssuerDN = new X509Name($"CN={issuer} Root");
				BigInteger serialNo = new BigInteger("1", 10);
				X509V3CertificateGenerator gen = new X509V3CertificateGenerator();

				gen.SetSerialNumber(serialNo);
				gen.SetIssuerDN(IssuerDN);
				gen.SetNotAfter(dateEnd);
				gen.SetNotBefore(dateBegin);
				gen.SetSubjectDN(IssuerDN);
				gen.SetPublicKey(pair.Public);

				ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA512WITHRSA",
					pair.Private, new SecureRandom(new CryptoApiRandomGenerator()));
				X509Certificate myCert = gen.Generate(signatureFactory);

				TextWriter textWriterGenCert = new StringWriter();
				PemWriter pemWriterGenCert = new PemWriter(textWriterGenCert);
				pemWriterGenCert.WriteObject(myCert);
				pemWriterGenCert.Writer.Flush();
				return textWriterGenCert.ToString();
			}
			catch (Exception ex)
			{
				LastError = ex.Message;
				return null;
			}
		}

		/// <summary>
		/// Создает само подписной сертификат CA.
		/// </summary>
		/// <param name="secretKey"></param>
		/// <param name="publicKey"></param>
		/// <param name="password"></param>
		/// <param name="issuer"></param>
		/// <param name="dateBegin"></param>
		/// <param name="dateEnd"></param>
		/// <returns></returns>
		public string GenCert(string secretKey, AsymmetricKeyParameter publicKey, string password,
			string issuer, DateTime dateBegin, DateTime dateEnd)
		{
			if (string.IsNullOrEmpty(secretKey))
			{
				LastError = "Поле закрытого ключа не заполнено";
				return null;
			}

			if (string.IsNullOrEmpty(password))
			{
				LastError = "Не указан пароль";
				return null;
			}

			if (string.IsNullOrEmpty(issuer))
			{
				LastError = "Не указано кем и кому выдан сертификат";
				return null;
			}
			
			try
			{
				TextReader readerPrivateKey = new StringReader(secretKey);
				PemReader pemReaderPrivateKey = new PemReader(readerPrivateKey, new PasswordFinder(password));
				AsymmetricKeyParameter privateKey = ((AsymmetricCipherKeyPair)pemReaderPrivateKey.ReadObject()).Private;
				AsymmetricCipherKeyPair pair = new AsymmetricCipherKeyPair(publicKey, privateKey);

				X509Name IssuerDN = new X509Name($"CN={issuer} Root");
				BigInteger serialNo = new BigInteger("1", 10);
				X509V3CertificateGenerator gen = new X509V3CertificateGenerator();

				gen.SetSerialNumber(serialNo);
				gen.SetIssuerDN(IssuerDN);
				gen.SetNotAfter(dateEnd);
				gen.SetNotBefore(dateBegin);
				gen.SetSubjectDN(IssuerDN);
				gen.SetPublicKey(pair.Public);

				ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA512WITHRSA", 
					pair.Private, new SecureRandom(new CryptoApiRandomGenerator()));
				X509Certificate myCert = gen.Generate(signatureFactory);

				TextWriter textWriterGenCert = new StringWriter();
				PemWriter pemWriterGenCert = new PemWriter(textWriterGenCert);
				pemWriterGenCert.WriteObject(myCert);
				pemWriterGenCert.Writer.Flush();
				return textWriterGenCert.ToString();
			}
			catch (Exception ex)
			{
				LastError = ex.Message;
				return null;
			}
		}

		/// <summary>
		/// Генерирует криптографически устойчивую случайную последовательность.
		/// </summary>
		/// <param name="length"></param>
		/// <returns></returns>
		public byte[] GenerateRandom(int length)
		{
			byte[] result = new byte[length];
			SecureRandom sr = new SecureRandom(new CryptoApiRandomGenerator());
			sr.NextBytes(result);
			return result;
		}

		/// <summary>
		/// Шифрует сообщение алгоритмом RSA используя закрытый ключ.
		/// Фактически это усеченный алгоритм подписи(без хеш). Расшифровать можно 
		/// открытым ключем. Как и проверка подписи.  Подписывать нельзя так как длина
		/// сообщения будет равна длине текста.
		/// Для нормального шифрования используется открытый ключ получателя.
		/// </summary>
		/// <param name="pathPrivateKey"></param>
		/// <param name="data"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		public byte[] EncryptRsaUsePrivateKey(string pathPrivateKey, byte[] data, string password)
		{
			if (!File.Exists(pathPrivateKey))
			{
				LastError = "По указанному пути закрытый ключ не найден";
				return null;
			}
			try
			{
				var encryptEngine = new Pkcs1Encoding(new RsaEngine());
				var keyPair = (AsymmetricCipherKeyPair)LoadPem(pathPrivateKey, password);
				encryptEngine.Init(true, keyPair.Private);
				return encryptEngine.ProcessBlock(data, 0, data.Length);
			}
			catch (Exception ex)
			{
				LastError = ex.Message;
				return null;
			}
		}

		public byte[] DecryptRsaUsePublicKey(byte[] data, AsymmetricKeyParameter publicKey)
		{
			var decryptEngine = new Pkcs1Encoding(new RsaEngine());
			decryptEngine.Init(false, publicKey);
			return decryptEngine.ProcessBlock(data, 0, data.Length);
		}

		public byte[] EncryptRsaUsePublicKey(byte[] data, AsymmetricKeyParameter publicKey)
		{
			var encryptEngine = new Pkcs1Encoding(new RsaEngine());
			encryptEngine.Init(true, publicKey);

			return encryptEngine.ProcessBlock(data, 0, data.Length);
		}

		public byte[] DecryptRsaUsePrivateKey(byte[] data, AsymmetricKeyParameter privateKey)
		{
			var decryptEngine = new Pkcs1Encoding(new RsaEngine());
			decryptEngine.Init(false, privateKey);
			return decryptEngine.ProcessBlock(data, 0, data.Length);
		}

		/// <summary>
		/// Шифрует алгоритмом AES.
		/// </summary>
		/// <param name="data"></param>
		/// <param name="key"></param>
		/// <param name="iv"></param>
		/// <returns></returns>
		public byte[] EncryptAes(byte[] data, byte[] key, byte[] iv)
		{
			BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesFastEngine()));
			ParametersWithIV piv = new ParametersWithIV((new KeyParameter(key)), iv);
			cipher.Init(true, piv);
			byte[] result = new byte[cipher.GetOutputSize(data.Length)];
			int len = cipher.ProcessBytes(data, 0, data.Length, result, 0);
			try
			{
				cipher.DoFinal(result, len);
			}
			catch (Exception ex)
			{
				LastError = ex.Message;
				return null;
			}

			return result;
		}

		/// <summary>
		/// Дешифрует алгоритмом AES.
		/// </summary>
		/// <param name="data"></param>
		/// <param name="key"></param>
		/// <param name="iv"></param>
		/// <returns></returns>
		public byte[] DecryptAes(byte[] data, byte[] key, byte[] iv)
		{
			BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesFastEngine()));

			ParametersWithIV piv = new ParametersWithIV((new KeyParameter(key)), iv);
			cipher.Init(false, piv);
			byte[] result = new byte[cipher.GetOutputSize(data.Length)];
			int len = cipher.ProcessBytes(data, 0, data.Length, result, 0);
			try
			{
				cipher.DoFinal(result, len);
			}
			catch (Exception ex)
			{
				LastError = ex.Message;
				return null;
			}

			return result;
		}

		/// <summary>
		/// Возвращает значение хэш функции Sha512.
		/// </summary>
		/// <param name="data"></param>
		/// <returns></returns>
		public byte[] Sha512Digest(byte[] data)
		{
			Sha512Digest sha = new Sha512Digest();
			sha.BlockUpdate(data, 0, data.Length);
			byte[] result = new byte[sha.GetDigestSize()];
			sha.DoFinal(result, 0);
			return result;
		}
	}
}
