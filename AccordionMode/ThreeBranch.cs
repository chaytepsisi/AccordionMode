using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AccordionMode
{
    internal class ThreeBranch
    {
        byte[][] FillBranches(byte[] input)
        {
            byte[] p0, p1, pBar;
            if (input.Length > Constants.BLOCK_BYTE_SIZE * 2)
            {
                p0 = input.Take(Constants.BLOCK_BYTE_SIZE).ToArray();
                p1 = input.Skip(Constants.BLOCK_BYTE_SIZE).Take(Constants.BLOCK_BYTE_SIZE).ToArray();
                pBar = input.Skip(2 * Constants.BLOCK_BYTE_SIZE).ToArray();
            }
            else
            {
                p0 = new byte[Constants.BLOCK_BYTE_SIZE];
                p1= new byte[Constants.BLOCK_BYTE_SIZE];
                pBar= new byte[Constants.BLOCK_BYTE_SIZE];
            }
                return new byte[][] { p0, p1, pBar };
        }

        byte[] Hash(byte[] pBar, byte[] tag, byte[] key)
        {
            var hashAlg = SHA256.Create();
            var hashVal = hashAlg.ComputeHash(pBar.Concat(tag).Concat(key).ToArray());

            return hashVal;

        }

        static byte[] Encrypt(byte[] pText, byte[] Key, byte[] IV=null)
        {
            byte[] encrypted;
            if (IV == null)
            {
                IV = new byte[Constants.BLOCK_BYTE_SIZE];
                for (int i = 0; i < IV.Length; i++)
                {
                    IV[i] = 0x0;
                }
            }
            using (AesManaged aes = new AesManaged())
            {
                ICryptoTransform encryptor = aes.CreateEncryptor(Key, IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                            sw.Write(pText);
                        encrypted = ms.ToArray();
                    }
                }
            }
            return encrypted;
        }

        static byte[] GenerateKeyStream(byte[] seed, int byteLength)
        {
            var keyStream = new byte[byteLength];
            for (int i = 0; i < keyStream.Length; i++)
                keyStream[i] = 0x00;

            return keyStream;
        }

        public byte[] Encipher(byte[] pText, byte[] key, byte[] tag)
        {
            var input = FillBranches(pText);

            var tempBar = Hash(input[2], tag, key);
            input[0] = Commons.Xor(input[0], tempBar.Take(Constants.BLOCK_BYTE_SIZE).ToArray());
            input[1] = Commons.Xor(input[1], tempBar.Skip(Constants.BLOCK_BYTE_SIZE).Take(Constants.BLOCK_BYTE_SIZE).ToArray());

            input[0] = Encrypt(input[0], key);
            input[1] = Encrypt(input[1], key);

            var keyStreamSeed = Commons.Xor(input[0], input[1]);
            var keyStream = GenerateKeyStream(keyStreamSeed, input[2].Length);
            var cBar = Commons.Xor(keyStream, input[2]);

            tempBar = Hash(cBar, tag, key);
            input[0] = Commons.Xor(input[0], tempBar.Take(Constants.BLOCK_BYTE_SIZE).ToArray());
            input[1] = Commons.Xor(input[1], tempBar.Skip(Constants.BLOCK_BYTE_SIZE).Take(Constants.BLOCK_BYTE_SIZE).ToArray());

            var c0 = Encrypt(input[0], key);
            var c1 = Encrypt(input[1], key);


            return c0.Concat(c1).Concat(cBar).ToArray();
        }
    }
}
