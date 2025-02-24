using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AccordionMode
{
    internal class BlockCipherManager
    {

        public AesManaged CreateAesManaged(byte[] key, byte[] iv)
        {
            return new AesManaged
            {
                KeySize = Constants.KEY_BYTE_SIZE * 8,
                Key = key,
                BlockSize = Constants.BLOCK_BYTE_SIZE * 8,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.Zeros,
                IV = iv
            };
        }
        public byte[] Encrypt(byte[] pText, byte[] Key, byte[] IV = null)
        {
            if (IV == null)
                IV = Commons.GenerateZeroIV(Constants.BLOCK_BYTE_SIZE);

            var aesAlg = CreateAesManaged(Key, IV);
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
            return encryptor.TransformFinalBlock(pText, 0, pText.Length);

        }

        public byte[] Decrypt(byte[] cText, byte[] Key, byte[] IV = null)
        {
            if (IV == null)
                IV = Commons.GenerateZeroIV(Constants.BLOCK_BYTE_SIZE);

            var aesAlg = CreateAesManaged(Key, IV);
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
            return decryptor.TransformFinalBlock(cText, 0, cText.Length);
        }
    }
}
