using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using MySecurityBE.cifrados;
using MySecurityBE.decifrado.impl;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.ComponentModel;
using System.Security.Cryptography;

namespace Testing
{
    [TestClass]
    public class DecifradoTest
    {
        [TestMethod]
        public void DecifradoRSA()
        {
#error Especificar la ruta del certificado
            X509Certificate2 certificado = new X509Certificate2(@"", "");
            const string str = "RAGjQ9xxLRznMlh7Zfh+KGpBHK2vY/8JD59xpiiDtxtLQ9BSlMOAPPOGdvHJIsQjJ31kHLeZTjgXR/FTHoIQu82sGPlTp+bcrFRHnjlv3mYw0e3K9J489JSWC2NFjsoFcQSwo624q+mff4nihI2u2akd8DBlaofUiF0jrK1Rq+3FUdLp2m4DG+onyHco01SGrWA2sxL+9MbRRAhRM1+fMQTJGE0O2ybt59XmXZethEIxAS60UJ/nZ0Qi+rh5P948ejeE+hL9KAUrvE+FDIqcpXzDrpJMVEmjS9LMkVKLDHDNWyAssi0PPEyfvHJW0UoppZhJPPr76AgFfYKzQ+eyjg==";

            var rsa = certificado.PrivateKey as RSACryptoServiceProvider;
            var decodedData = rsa.Decrypt(Convert.FromBase64String(str), true);

            var decodedStr = Encoding.UTF8.GetString(decodedData);

            ICifrado<byte[]> aes = new AES128Manejador()
            {
                Key = decodedData
            };

            byte[] descifrado = aes.descifrar(
                "1rbvF/iGKyfWS8gp323AVskNdTODm/87fq7/2BURYFE="
                );

            Encoding.UTF8.GetString(descifrado);

            descifrado = aes.descifrar(
               "x7W+C/Rq/Pt+rYF1coKjmP082WLWwT6CHY87Xhq9cXsN0ZxSu/YJG1bXWrjPnml4iSUIZKOBLXf+1ARHl27W0IiiNzOAbH2f+x8TAZu53eusNGCdgzvlM3QKIUS6Mx6/b4fMOoFt8dNv4K3DalcVhksGLzVH/uMvyQHT71MYet+Kp2Buf17BFE3ARFLbGi4EGHvoEXMjEIorp0ZojDqaaZcoqh8IP7YrvoBwIOk40qeJYE2wMxMdT0Zpqu+NZQbEouJEGWhrZ+sJX2ik0uyhc5pL1uVHoeme9xXeBtaW6xKSJM0SUuKWtttnXsOHA2vLDa2uu8iwNe+lxVwklsyQRl38d+PTXiNoNgxCaf3eazA++AmwoectzCoKh6ljqs7cBwzLR+TOWutovAHYETDwA6cfPBwqlGOUsCrx+e8ENR4="

               );

            Assert.IsNull(Encoding.UTF8.GetString(descifrado));






        }

        [TestMethod]
        public void PruebaRSA()
        {
            #error Especificar la ruta del certificado
            X509Certificate2 certificado = new X509Certificate2(@"", "");

            const string str = "Test";
            var rsa = certificado.PrivateKey as RSACryptoServiceProvider;
            var encodedData = rsa.Encrypt(Encoding.UTF8.GetBytes(str), false);
            var encodedString = Convert.ToBase64String(encodedData);
            var decodedData = rsa.Decrypt(Convert.FromBase64String(encodedString), false);
            var decodedStr = Encoding.UTF8.GetString(decodedData);
            Assert.AreEqual(str, decodedStr);







        }
    }
}
