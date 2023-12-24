using HybridCryptLib.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
		public void Crypt(UserInfo info)
		{
			string json = JsonConvert.SerializeObject(info);
		}
	}
}
