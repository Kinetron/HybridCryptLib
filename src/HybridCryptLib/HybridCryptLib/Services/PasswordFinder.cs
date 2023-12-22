using Org.BouncyCastle.OpenSsl;

namespace HybridCryptLib.Services
{
	internal class PasswordFinder : IPasswordFinder
	{
		private readonly char[] _password;
		public PasswordFinder(string pass)
		{
			_password = pass.ToCharArray();
		}
		public char[] GetPassword()
		{
			return _password;
		}
	}
}
