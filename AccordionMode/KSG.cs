using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Text;
using System.Threading.Tasks;

namespace AccordionMode
{
    public class KSG
    {
        public byte[] Seed { get; set; }
        public byte[] Key { get; set; }
        public int KeyStreamLength { get; set; }
        public KSG(byte[] seed, byte[] key)
        {
            Seed = (byte[])seed.Clone();
            Key = (byte[])key.Clone();
        }

        public byte[] GenerateKeyStream(int KeyStreamLength)
        {

            var aesAlg = new AesManaged
            {
                KeySize = Constants.KEY_BYTE_SIZE * 8,
                Key = this.Key,
                BlockSize = Constants.BLOCK_BYTE_SIZE * 8,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.Zeros,
                IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
            };

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
            int limit = (int)Math.Ceiling(KeyStreamLength * 1.0 / Constants.BLOCK_BYTE_SIZE);

            List<byte> output = new List<byte>();
            for (int i = 0; i < limit; i++)
            {
                if (i != 0)
                    Seed = Commons.IncrementArray(Seed);
                output.AddRange(encryptor.TransformFinalBlock(Seed, 0, Seed.Length));
            }
            if (output.Count > KeyStreamLength)
                return output.Take(KeyStreamLength).ToArray();
            return output.ToArray();
        }
    }
}
