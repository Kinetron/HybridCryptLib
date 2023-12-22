using HybridCryptLib.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HybridCryptLib.Tests
{
	public class LibTests
	{
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
	}
}
