using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AccordionMode
{
    public class Commons
    {
        public static byte[] Xor(byte[] arr1, byte[] arr2)
        {
            if (arr1.Length == arr2.Length)
            {
                byte[] result = new byte[arr1.Length];
                for (int i = 0; i < result.Length; i++)
                    result[i] = (byte)(arr1[i] ^ arr2[i]);
                return result;
            }
            else
            {
                if (arr1.Length < arr2.Length)
                {
                    byte[] tempArr = new byte[arr1.Length];
                    Array.Copy(arr1, tempArr, arr1.Length);
                    arr1 = (byte[])arr2.Clone();
                    arr2 = (byte[])tempArr.Clone();
                }
                byte[] result = new byte[arr1.Length];
                for (int i = 0; i < result.Length; i++)
                {
                    if (i > arr2.Length)
                        result[i] = arr1[i];
                    else result[i] = (byte)(arr1[i] ^ arr2[i]);
                }
                return result;

            }
        }
        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static byte[] IncrementArray(byte[] arr)
        {
            for (int i = arr.Length - 1; i >= 0; i--)
            {
                if (arr[i] == 255)
                    arr[i] = 0;
                else
                {
                    arr[i]++;
                    break;
                }
            }
            return arr;

        }
    }
}
