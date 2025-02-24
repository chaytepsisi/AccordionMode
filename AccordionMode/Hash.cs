using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AccordionMode
{
    internal class Hash
    {
        public byte[] Input { get; set; }
        public byte[] Tag{ get; set; }
        public byte[] Key { get; set; }
        public Hash(byte[] pBar, byte[] tag, byte[] key)
        {
            Input = pBar;
            Tag = tag;
            Key = key;
        }

        public byte[] Create()
        {
            var hashAlg = SHA256.Create();
            var hashVal = hashAlg.ComputeHash(Input.Concat(Tag).Concat(Key).ToArray());
            return hashVal;
        }
    }
}
