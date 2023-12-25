using HybridCryptLib.Models;
using HybridCryptLib.ShortAsn.Enums;
using HybridCryptLib.ShortAsn;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace HybridCryptLib.Services
{
	/// <summary>
	/// Шифрует пользовательские данные.
	/// </summary>
	public class CryptUserInfo
	{
		/// <summary>
		/// Шифрует пользовательские данные.
		/// </summary>
		/// <param name="info"></param>
		public byte[] Crypt(UserInfo info, string certPath)
		{
			string json = JsonConvert.SerializeObject(info);

			СommonCrypt сommonCrypt = new СommonCrypt();

			//Генерируем ключ шифрования для блочного шифра.
			byte[] aesKey = сommonCrypt.GenerateRandom(32);
			byte[] iv = сommonCrypt.GenerateRandom(16); //Начальный вектор.
			byte[] cryptResult = сommonCrypt.EncryptAes(Encoding.UTF8.GetBytes(json), aesKey, iv);

			AsymmetricKeyParameter publicKey = null;

			//Открытый ключ читаем из сертификата.
			using (FileStream file = File.OpenRead(certPath))
			{
				X509CertificateParser parser = new X509CertificateParser();
				var certificate = parser.ReadCertificate(file);
				publicKey = certificate.GetPublicKey();
			}

			byte[] cryptSessionKey = сommonCrypt.EncryptRsaUsePublicKey(aesKey, publicKey);

			BlockManager blockManager = new BlockManager();
			blockManager.AddBlock(cryptResult, BlockTypesEnum.DataBlock);
			blockManager.AddBlock(iv, BlockTypesEnum.InitVector);
			blockManager.AddBlock(cryptSessionKey, BlockTypesEnum.CryptSessionKey);

			return blockManager.GetData();
		}

		/// <summary>
		/// Декодирует пользовательские данные.
		/// </summary>
		/// <param name="data"></param>
		/// <param name="privateKeyPath"></param>
		/// <param name="privateKeyPassword"></param>
		/// <returns></returns>
		public UserInfo DeCrypt(byte[] data, string privateKeyPath, string privateKeyPassword)
		{
			BlockManager blockManager = new BlockManager();
			blockManager.ReadData(data);

			byte[] iv = blockManager.Blocks.FirstOrDefault(x=>x.Type == BlockTypesEnum.InitVector)?.Data; //Начальный вектор.
			byte[] cryptSessionKey = blockManager.Blocks.FirstOrDefault(x => x.Type == BlockTypesEnum.CryptSessionKey)?.Data;
			byte[] cryptData = blockManager.Blocks.FirstOrDefault(x => x.Type == BlockTypesEnum.DataBlock)?.Data;

			СommonCrypt сommonCrypt = new СommonCrypt();
			AsymmetricCipherKeyPair pair = сommonCrypt.LoadPem(privateKeyPath, privateKeyPassword) as AsymmetricCipherKeyPair;

			byte[] aesKey = сommonCrypt.DecryptRsaUsePrivateKey(cryptSessionKey, pair.Private);
			byte[] decryptResult = сommonCrypt.DecryptAes(cryptData, aesKey, iv);

			string json = Encoding.UTF8.GetString(decryptResult);

			return JsonConvert.DeserializeObject<UserInfo>(json);
		}
	}
}
