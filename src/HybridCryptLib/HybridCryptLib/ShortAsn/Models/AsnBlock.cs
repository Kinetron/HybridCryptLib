using HybridCryptLib.ShortAsn.Enums;

namespace HybridCryptLib.ShortAsn.Models
{
	/// <summary>
	/// Бинарный блок.
	/// </summary>
	internal class AsnBlock
	{
		/// <summary>
		/// Тип блока.
		/// </summary>
		public BlockTypesEnum Type { get; set; }

		/// <summary>
		/// Данные блока.
		/// </summary>
		public byte[] Data { get; set; }
	}
}
