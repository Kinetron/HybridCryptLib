using HybridCryptLib.ShortAsn;
using HybridCryptLib.ShortAsn.Enums;

namespace HybridCryptLib.Tests
{
    internal class ShortAsnTests
    {
		/// <summary>
		/// Тест кодирования декодирования информации в блоки.
		/// </summary>
		[Test]
	    public void CodeDecodeTest()
	    {
		    Random rnd = new Random();
		    byte[] sourceData = new byte[108 * 1024]; //В килобайтах.
		    rnd.NextBytes(sourceData);

		    BlockManager blockManager = new BlockManager();
			blockManager.AddBlock(sourceData, BlockTypesEnum.DataBlock);
			blockManager.AddBlock(sourceData, BlockTypesEnum.CryptSessionKey);

			byte[] resultData = blockManager.GetData(); //Формирую Asn1 последовательность.
			blockManager.Blocks.Clear();
			
			blockManager.ReadData(resultData);

			Assert.AreEqual(2, blockManager.Blocks.Count);

			Assert.IsTrue(sourceData.SequenceEqual(blockManager.Blocks[0].Data));
			Assert.IsTrue(sourceData.SequenceEqual(blockManager.Blocks[1].Data));
	    }
    }
}
