using System;
using System.ServiceModel.Channels;
using System.Xml;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.Xml;
using MySecurityBE.enconding;
using System.IO;
using MySecurityBE.cifrados;
using MySecurityBE.decifrado.impl;
using System.Text;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace CertFixEscapedComma
{
    public class CertRefEncoder : MessageEncoder
    {
        //private const string SECURITY_NAMESPACE = "http://ScottsSecurity";
        private const string SECURITY_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        private const string SECURITY_UTILITY_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

        public MessageEncoder innerEncoder { get; set; }
        private XmlWriterSettings writerSettings;

        #region Spring
        public X509Certificate2 certificado { get; set; }
        public Dictionary<string, string> namespaces { get; set; }
        public ICifrado<byte[]> cypher { get; set; }
        #endregion

        public CertRefEncoder(MessageEncoder innerEnc)
        {
            innerEncoder = innerEnc;

            writerSettings = new XmlWriterSettings();
            writerSettings.Encoding = Encoding.UTF8;
            if (innerEnc == null)
                throw new ArgumentNullException("innerEnc");
        }
        public CertRefEncoder()
        {
            innerEncoder = (new TextMessageEncodingBindingElement()).CreateMessageEncoderFactory().Encoder;

            writerSettings = new XmlWriterSettings();
            writerSettings.Encoding = Encoding.UTF8;
        }

        public override string ContentType
        {
            get { return innerEncoder?.ContentType; }
        }

        public override string MediaType
        {
            get { return innerEncoder?.MediaType; }
        }

        public override MessageVersion MessageVersion
        {
            get { return innerEncoder?.MessageVersion; }
        }

        public override Message ReadMessage(ArraySegment<byte> buffer, BufferManager bufferManager, string contentType)
        {

            byte[] msgContents = new byte[buffer.Count];
            Array.Copy(buffer.Array, buffer.Offset, msgContents, 0, msgContents.Length);
            bufferManager.ReturnBuffer(buffer.Array);
            MemoryStream stream = new MemoryStream(msgContents);
            Message msg = ReadMessage(stream, int.MaxValue);
            XmlDocument messageOriginal = new XmlDocument();
            messageOriginal.PreserveWhitespace = true;
            messageOriginal.LoadXml(msg.ToString());
            if (validateFirma(messageOriginal))
            {
                try
                {
                    int secHeaderIndex = msg.Headers.FindHeader("Security", SECURITY_NAMESPACE);
                    //Remuevo la Security
                    msg.Headers.RemoveAt(secHeaderIndex);
                    var reader = msg.GetReaderAtBodyContents();
                    XmlNodeList encryptedKey = messageOriginal.DocumentElement.SelectNodes("//*[local-name()='EncryptedKey']");
                    var rsa = certificado.PrivateKey as RSACryptoServiceProvider;
                    foreach (XmlNode nodo in encryptedKey)
                    {
                        var encryptdData = nodo.SelectNodes("//*[local-name()='CipherData']");
                        if (encryptdData.Count >= 1)
                        {
                            var decodedData = rsa.Decrypt(Convert.FromBase64String(encryptdData[0].InnerText), true);
                            XmlDocument body = new XmlDocument();
                            body.PreserveWhitespace = false;
                            XmlNode secNode = body.ReadNode(reader);
                            body.LoadXml(secNode.OuterXml);
                            var text = body.InnerText;
                            cypher.Key = decodedData;

                            byte[] descifrado = cypher.descifrar(text);
                            String desencriptado = Encoding.UTF8.GetString(descifrado);
                            string prefix = getPrefix(desencriptado);
                            desencriptado = desencriptado.Substring(desencriptado.IndexOf("<" + prefix), desencriptado.Length - desencriptado.IndexOf("<" + prefix));
                            msg = Message.CreateMessage(msg.Version, "", new SimpleMessageBody(desencriptado));
                        }
                    }
                }
                catch (Exception)
                {
                    throw;
                }
            }
            return msg;
        }
        public string getPrefix(string desencriptado)
        {
            string prefix = "";
            string _namespace = namespaces["valid"];

            if (!desencriptado.Contains(_namespace))
            {
                _namespace = namespaces["invalid"];
                if (!desencriptado.Contains(_namespace))
                    return "";
            }

            int final = desencriptado.IndexOf(_namespace) - 3;
            char c = desencriptado[final];

            while (c != ':')
            {
                prefix = c + prefix;
                final--;
                c = desencriptado[final];
            }
            return prefix;
        }
        public override Message ReadMessage(Stream stream, int maxSizeOfHeaders, string contentType)
        {

            return innerEncoder?.ReadMessage(stream, maxSizeOfHeaders, contentType);
        }

        private bool validateFirma(XmlDocument messageOriginal)
        {
            bool salida = true;

            XmlNodeList BinarySecurityTokens = messageOriginal.DocumentElement.SelectNodes("//*[local-name()='BinarySecurityToken']");
            XmlNodeList Signatures = messageOriginal.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#");
            List<X509Certificate2> certificados = new List<X509Certificate2>();
            foreach (XmlNode BinarySecurityToken in BinarySecurityTokens)
            {
                var valueCertificate = BinarySecurityToken.InnerText;
                X509Certificate2 dcert2 = new X509Certificate2(Convert.FromBase64String(valueCertificate));
                certificados.Add(dcert2);
            }

            if (BinarySecurityTokens.Count > 1)
            {
                X509Certificate2 certificado = certificados.Last();
                if (certificado != null)
                {
                    //Corregir firma
                    foreach (XmlElement element in Signatures)
                    {
                        SignedXmlWithId signedXml = new SignedXmlWithId(messageOriginal);
                        signedXml.LoadXml(element);
                        salida = signedXml.CheckSignature(certificado.PublicKey.Key);
                        if (salida == false) break;
                    }

                }
            }
            return true;
        }

        public override ArraySegment<byte> WriteMessage(Message message, int maxMessageSize, BufferManager bufferManager, int messageOffset)
        {
            ArraySegment<byte> arseg = this.innerEncoder.WriteMessage(message, maxMessageSize, bufferManager, messageOffset);
            return arseg;
        }

        public override void WriteMessage(Message message, System.IO.Stream stream)
        {
            this.innerEncoder?.WriteMessage(message, stream);
        }




        private static string ModifyIssuerName(string oldIssuerName)
        {
            oldIssuerName = oldIssuerName.Replace(@"\,", "[;]");

            string[] stringSeparator = new string[] { "," };
            string[] result;

            result = oldIssuerName.Split(stringSeparator, StringSplitOptions.None);
            int pieces = result.Length;


            for (int j = 0; j < pieces; j++)
            {
                if (result[j].Contains("[;]"))
                {
                    string[] innerSeparator = new string[] { "=" };
                    string[] result2;

                    result2 = result[j].Split(innerSeparator, StringSplitOptions.None);
                    int pieces2 = result2.Length;

                    for (int i = 0; i < pieces2; i++)
                    {
                        if (result2[i].Contains("[;]"))
                        {
                            result2[i] = result2[i].Replace(@"[;]", ",");
                            result2[i] = "\"" + result2[i] + "\"";
                        }
                    }

                    string res2 = result2[0];
                    for (int i = 1; i < pieces2; i++)
                    {
                        res2 = res2 + "=" + result2[i];
                    }

                    result[j] = res2;
                }

            }

            string res = result[0];
            for (int k = 1; k < pieces; k++)
            {
                res = res + "," + result[k];
            }

            return res;

        }


    }
}
