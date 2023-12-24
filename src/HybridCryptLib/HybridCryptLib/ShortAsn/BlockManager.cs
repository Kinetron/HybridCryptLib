using HybridCryptLib.ShortAsn.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using HybridCryptLib.ShortAsn.Enums;

namespace HybridCryptLib.ShortAsn
{
	/// <summary>
	/// Содержит основной функционал для работы с бинарными блоками похожими на формат Asn1.
	/// Формат немного упрощен, и использует свои типы блоков.
	/// </summary>
	internal class BlockManager
	{
		/// <summary>
		/// Длина типа блока. Байт.
		/// </summary>
		private const int TypeBlockLen = 1;

		/// <summary>
		/// Количество байт занимаемых сведениями о длине данных.
		/// </summary>
		private const int LenInfoSize = 4;

		/// <summary>
		/// Размер заголовка блоков(заголовок состоит из типа блока, длины данных), в байтах.
		/// </summary>
		private const int BlockHeadSize = 5;

		/// <summary>
		/// Начало информации о типе блока.
		/// </summary>
		private const int BlockTypeBeginPos = 0;

		/// <summary>
		///Блоки данных
		/// </summary>
		public List<AsnBlock> Blocks;

		public BlockManager()
		{
			Blocks = new List<AsnBlock>();
		}

		/// <summary>
		/// Добавляет новый блок данных.
		/// </summary>
		/// <param name="data"></param>
		/// <param name="type"></param>
		public void AddBlock(byte[] data, BlockTypesEnum type)
		{
			Blocks.Add(new AsnBlock()
			{
				Type = type,
				Data = data
			});
		}

		/// <summary>
		/// На основании блоков формирует бинарную последовательность в формате ASN1.
		/// [тип блока  1 байт][длина данных 4 байта][данные]
		/// </summary>
		/// <returns></returns>
		public byte[] GetData()
		{
			int size = 0;
			Blocks.ForEach((x) =>
			{
				size += x.Data.Length + TypeBlockLen + LenInfoSize;
			});

			byte[] data = new byte[size];
			int pos = 0;

			Blocks.ForEach((x) =>
			{
				//Тип блока.
				data[pos] = (byte)x.Type;
				pos++;

				//Добавляю длину блока данных.
				byte[] dataLen = GetBlockLen(x.Data);
				
				if (dataLen.Length != TypeBlockLen)
				{
					new ArgumentException("Bad block len result.");
				}
				Buffer.BlockCopy(dataLen, 0, data, pos, dataLen.Length);
				pos += dataLen.Length;

				//Данные.
				Buffer.BlockCopy(x.Data, 0, data, pos, x.Data.Length);
				pos += x.Data.Length;
			});

			return data;
		}

		/// <summary>
		/// Возвращает длину блока данных.
		/// </summary>
		/// <param name="block"></param>
		/// <returns></returns>
		private byte[] GetBlockLen(byte[] block)
		{
			int len = block.Length;
			return BitConverter.GetBytes(len);
		}

		/// <summary>
		/// Читает данные ассиметричной системы.
		/// </summary>
		public void ReadData(FileStream inFile, ulong dataLen)
		{
			//Устанавливаю текущую позицию на начало блока данных.
			inFile.Position = (long)dataLen;

			byte[] title = new byte[BlockHeadSize]; //Заголовок 5 байт [тип][длина] 

			int blockLen = 0; //Длина блока данных.

			//Файл может содержать произвольное количество блоков данных.
			while (inFile.Position < inFile.Length)
			{
				inFile.Read(title, 0, BlockHeadSize);

				//Читаю блок данных.
				blockLen = DecodeBlockDataLen(title);
				AsnBlock block = new AsnBlock();
				block.Type = (BlockTypesEnum)title[BlockTypeBeginPos];
				block.Data = new byte[blockLen];

				inFile.Read(block.Data, 0, blockLen);
				Blocks.Add(block);
			}
		}

		/// <summary>
		/// Получаю длину блока данных.
		/// </summary>
		/// <param name="asTitle"></param>
		/// <returns></returns>
		private static int DecodeBlockDataLen(byte[] asTitle)
		{
			//Заголовок 5 байт [тип][длина] 
			return BitConverter.ToInt32(asTitle, 1);
		}

	}
}
