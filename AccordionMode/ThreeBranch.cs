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
                p1 = new byte[Constants.BLOCK_BYTE_SIZE];
                pBar = new byte[Constants.BLOCK_BYTE_SIZE];
            }
            return new byte[][] { p0, p1, pBar };
        }

        byte[] Hash(byte[] pBar, byte[] tag, byte[] key)
        {
            var hashAlg = SHA256.Create();
            var hashVal = hashAlg.ComputeHash(pBar.Concat(tag).Concat(key).ToArray());

            return hashVal;

        }

        static byte[] Encrypt(byte[] pText, byte[] Key, byte[] IV = null)
        {
            if (IV == null)
            {
                IV = new byte[Constants.BLOCK_BYTE_SIZE];
                for (int i = 0; i < IV.Length; i++)
                {
                    IV[i] = 0x0;
                }
            }

            var aesAlg = new AesManaged
            {
                KeySize = Constants.KEY_BYTE_SIZE * 8,
                Key = Key,
                BlockSize = Constants.BLOCK_BYTE_SIZE * 8,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.Zeros,
                IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
            };

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
            return encryptor.TransformFinalBlock(pText, 0, pText.Length);

        }

        static byte[] Decrypt(byte[] cText, byte[] Key, byte[] IV = null)
        {
            if (IV == null)
            {
                IV = new byte[Constants.BLOCK_BYTE_SIZE];
                for (int i = 0; i < IV.Length; i++)
                {
                    IV[i] = 0x0;
                }
            }
            var aesAlg = new AesManaged
            {
                KeySize = Constants.KEY_BYTE_SIZE * 8,
                Key = Key,
                BlockSize = Constants.BLOCK_BYTE_SIZE * 8,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.Zeros,
                IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
            };

            ICryptoTransform encryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
            return encryptor.TransformFinalBlock(cText, 0, cText.Length);
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

            KSG keyStreamGenerator = new KSG(keyStreamSeed, key);
            var keyStream = keyStreamGenerator.GenerateKeyStream(input[2].Length);
            var cBar = Commons.Xor(keyStream, input[2]);

            tempBar = Hash(cBar, tag, key);
            input[0] = Commons.Xor(input[0], tempBar.Take(Constants.BLOCK_BYTE_SIZE).ToArray());
            input[1] = Commons.Xor(input[1], tempBar.Skip(Constants.BLOCK_BYTE_SIZE).Take(Constants.BLOCK_BYTE_SIZE).ToArray());

            var c0 = Encrypt(input[0], key);
            var c1 = Encrypt(input[1], key);


            return c0.Concat(c1).Concat(cBar).ToArray();
        }

        public byte[] Decipher(byte[] cText, byte[] key, byte[] tag)
        {
            var input = FillBranches(cText);

            input[0] = Decrypt(input[0], key);
            input[1] = Decrypt(input[1], key);

            var tempBar = Hash(input[2], tag, key);
            input[0] = Commons.Xor(input[0], tempBar.Take(Constants.BLOCK_BYTE_SIZE).ToArray());
            input[1] = Commons.Xor(input[1], tempBar.Skip(Constants.BLOCK_BYTE_SIZE).Take(Constants.BLOCK_BYTE_SIZE).ToArray());

            var keyStreamSeed = Commons.Xor(input[0], input[1]);

            KSG keyStreamGenerator = new KSG(keyStreamSeed, key);
            var keyStream = keyStreamGenerator.GenerateKeyStream(input[2].Length);
            var pBar = Commons.Xor(keyStream, input[2]);

            input[0] = Decrypt(input[0], key);
            input[1] = Decrypt(input[1], key);

            tempBar = Hash(pBar, tag, key);
            var p0 = Commons.Xor(input[0], tempBar.Take(Constants.BLOCK_BYTE_SIZE).ToArray());
            var p1 = Commons.Xor(input[1], tempBar.Skip(Constants.BLOCK_BYTE_SIZE).Take(Constants.BLOCK_BYTE_SIZE).ToArray());


            return p0.Concat(p1).Concat(pBar).ToArray();
        }
    }
}
