using MySecurityBE.cifrados;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace MySecurityBE.decifrado.impl
{
    public class AES128Manejador : ICifrado<byte[]>
    {
        public byte[] Key
        {
            get;
            set;
        }

        public byte[] cifrar(byte[] text)
        {
            return null;
        }

        public byte[] descifrar(String text)
        {
            byte[] cipher = Convert.FromBase64String(text);
            try
            {
                //init AES 128
                RijndaelManaged aes128 = new RijndaelManaged();
                aes128.Mode = CipherMode.CBC;
                aes128.Padding = PaddingMode.None;


                //decrypt
                ICryptoTransform decryptor = aes128.CreateDecryptor(Key, null);
                MemoryStream ms = new MemoryStream(cipher);
                CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);

                byte[] plain = new byte[cipher.Length];
                int decryptcount = cs.Read(plain, 0, plain.Length);

                ms.Close();
                cs.Close();

                //return plaintext in String
                return plain;
            }
            catch (Exception)
            {

                throw;
            }
        }
    }
}
