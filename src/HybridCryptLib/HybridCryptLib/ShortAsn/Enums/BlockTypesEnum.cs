using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace HybridCryptLib.ShortAsn.Enums
{
    /// <summary>
    /// Типы бинарных блоков.
    /// </summary>
    internal enum BlockTypesEnum
    {
        /// <summary>
        /// Блок содержащий кодированные данные.
        /// </summary>
        DataBlock = 1,

        /// <summary>
        /// Шифрованный сеансовый ключ.
        /// </summary>
        CryptSessionKey = 2,

        /// <summary>
        /// Начальный вектор
        /// </summary>
        InitVector = 3
    }
}
