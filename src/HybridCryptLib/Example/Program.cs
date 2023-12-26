using HybridCryptLib.Services;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace Example
{
	internal class Program
	{
		private static readonly string _privateKeyPath = "private_key";
		private static readonly string _privateKeyPassword = "12345678";

		static void Main(string[] args)
		{
			Console.WriteLine("Создание сертификата");

			/*
			 * 1. Откройте Git Bash с сылкой на папку в которой требуется сохранить ключ.
			   2. Вставьте текст  ssh-keygen -t rsa -b 4096 -m pem
			   3. Попросить ввести имя, вводим ./private_key
			   4. Попросит пароль. 
			   5. В папке будут созданы два файла.
			     Удалить из файла begin и end
			 */

			CertCreate(_privateKeyPath, _privateKeyPassword, "userDataStorage.crt");
		}

		/// <summary>
		/// Создает сертификат.
		/// </summary>
		/// <param name="privateKeyPath"></param>
		/// <param name="privateKeyPassword"></param>
		private static void CertCreate(string privateKeyPath, string privateKeyPassword, string fileName)
		{
			СommonCrypt сommonCrypt = new СommonCrypt();
			AsymmetricCipherKeyPair pair = (AsymmetricCipherKeyPair)сommonCrypt.LoadPem(privateKeyPath, privateKeyPassword);

			DateTime certBegin = DateTime.Now; //Дата начала действия сертификата.
			DateTime certEnd = certBegin.AddYears(100);

			string certContent = сommonCrypt.GenRootCert(pair, "LocalServer", certBegin, certEnd);

			File.WriteAllText(fileName, certContent);
		}
	}
}
