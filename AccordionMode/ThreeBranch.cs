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

        public byte[] Encipher(byte[] pText, byte[] key, byte[] tag)
        {
            BlockCipherManager blockCipherManager = new BlockCipherManager();

            var input = FillBranches(pText);

            var hashFunc= new Hash(input[2], tag, key);
            var tempBar = hashFunc.Create();

            input[0] = Commons.Xor(input[0], tempBar.Take(Constants.BLOCK_BYTE_SIZE).ToArray());
            input[1] = Commons.Xor(input[1], tempBar.Skip(Constants.BLOCK_BYTE_SIZE).Take(Constants.BLOCK_BYTE_SIZE).ToArray());

            input[0] = blockCipherManager.Encrypt(input[0], key);
            input[1] = blockCipherManager.Encrypt(input[1], key);

            var keyStreamSeed = Commons.Xor(input[0], input[1]);
            KSG keyStreamGenerator = new KSG(keyStreamSeed, key);
            var keyStream = keyStreamGenerator.GenerateKeyStream(input[2].Length);
            var cBar = Commons.Xor(keyStream, input[2]);

            hashFunc = new Hash(cBar, tag, key);
            tempBar = hashFunc.Create();

            input[0] = Commons.Xor(input[0], tempBar.Take(Constants.BLOCK_BYTE_SIZE).ToArray());
            input[1] = Commons.Xor(input[1], tempBar.Skip(Constants.BLOCK_BYTE_SIZE).Take(Constants.BLOCK_BYTE_SIZE).ToArray());

            var c0 = blockCipherManager.Encrypt(input[0], key);
            var c1 = blockCipherManager.Encrypt(input[1], key);

            return c0.Concat(c1).Concat(cBar).ToArray();
        }

        public byte[] Decipher(byte[] cText, byte[] key, byte[] tag)
        {
            BlockCipherManager blockCipherManager = new BlockCipherManager();

            var input = FillBranches(cText);
            
            input[0] = blockCipherManager.Decrypt(input[0], key);
            input[1] = blockCipherManager.Decrypt(input[1], key);

            var hashFunc = new Hash(input[2], tag, key);
            var tempBar = hashFunc.Create();

            input[0] = Commons.Xor(input[0], tempBar.Take(Constants.BLOCK_BYTE_SIZE).ToArray());
            input[1] = Commons.Xor(input[1], tempBar.Skip(Constants.BLOCK_BYTE_SIZE).Take(Constants.BLOCK_BYTE_SIZE).ToArray());

            var keyStreamSeed = Commons.Xor(input[0], input[1]);
            KSG keyStreamGenerator = new KSG(keyStreamSeed, key);
            var keyStream = keyStreamGenerator.GenerateKeyStream(input[2].Length);
            var pBar = Commons.Xor(keyStream, input[2]);

            input[0] = blockCipherManager.Decrypt(input[0], key);
            input[1] = blockCipherManager.Decrypt(input[1], key);

            hashFunc = new Hash(pBar, tag, key);
            tempBar = hashFunc.Create();

            var p0 = Commons.Xor(input[0], tempBar.Take(Constants.BLOCK_BYTE_SIZE).ToArray());
            var p1 = Commons.Xor(input[1], tempBar.Skip(Constants.BLOCK_BYTE_SIZE).Take(Constants.BLOCK_BYTE_SIZE).ToArray());


            return p0.Concat(p1).Concat(pBar).ToArray();
        }
    }
}
