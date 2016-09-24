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
            if (msg.IsFault)
                return Message.CreateMessage(msg.Version, MessageFault.CreateFault(msg, int.MaxValue), "");
            string accion = "";
            //return msg;
            XmlDocument messageOriginal = new XmlDocument();
            messageOriginal.PreserveWhitespace = true;
            messageOriginal.LoadXml(msg.ToString());


            XmlNodeList encryptedKey = messageOriginal.DocumentElement.SelectNodes("//*[local-name()='EncryptedKey']");


            var reader = msg.GetReaderAtBodyContents();
            String desencriptado = "";


            XmlDocument body = new XmlDocument();
            body.PreserveWhitespace = false;
            XmlNode secNode = body.ReadNode(reader);
            body.LoadXml(secNode.OuterXml);

            XmlNode nodo = null;

            if (encryptedKey.Count > 0)
            {
                nodo = encryptedKey[0];
                var encryptdData = nodo.SelectNodes("//*[local-name()='CipherData']");
                if (encryptdData.Count >= 1)
                {
                    var rsa = certificado.PrivateKey as RSACryptoServiceProvider;
                    var decodedData = rsa.Decrypt(Convert.FromBase64String(encryptdData[0].InnerText), true);

                    var text = body.InnerText;
                    cypher.Key = decodedData;

                    byte[] descifrado = cypher.descifrar(text);
                    int start = 0, end = 0;
                    end = descifrado.Length;
                    if (end >= 3 && descifrado[0] == 0xEF && descifrado[1] == 0xBB && descifrado[2] == 0xBF)
                    {
                        start += 3;
                        end -= 3;
                        desencriptado = Encoding.UTF8.GetString(descifrado, start, end).Trim().Replace("\0", "");
                    }
                    else
                        desencriptado = Encoding.UTF8.GetString(descifrado, start, end).Trim().Replace("\0", "");
                    //string prefix = getPrefix(desencriptado);
                    int inicio = getInicio(desencriptado);
                    int badchars = getBadCharCount(desencriptado);
                    accion = getAction(inicio, desencriptado);
                    desencriptado = desencriptado.Substring(inicio, desencriptado.Length - badchars - inicio);
                }
            }
            else
            {
                desencriptado = secNode.OuterXml;
            }


            //XmlDocument otrobody = new XmlDocument();
            //otrobody.LoadXml(desencriptado);
            //XmlNode body2 = messageOriginal.ImportNode(otrobody.DocumentElement, true);

            //XmlNode body1 = messageOriginal.SelectNodes("//*[local-name()='Body']")[0];
            //XmlNode hijo = body1.FirstChild;
            //body1.RemoveChild(hijo);
            //body1.AppendChild(body2);

            //Verify(messageOriginal);//Debería ser un IF
            {
                try
                {
                    //int secHeaderIndex = msg.Headers.FindHeader("Security", SECURITY_NAMESPACE);
                    ////Remuevo la Security
                    //msg.Headers.RemoveAt(secHeaderIndex);
                    msg = Message.CreateMessage(msg.Version, accion, new SimpleMessageBody(desencriptado));
                }
                catch (Exception)
                {
                    throw;
                }
            }
            return msg;
        }
        //public string getPrefix(string desencriptado)
        //{
        //    string _namespace = namespaces["valid"];

        //    if (!desencriptado.Contains(_namespace))
        //    {
        //        _namespace = namespaces["invalid"];
        //        if (!desencriptado.Contains(_namespace))
        //            return "";
        //    }

        //    int final = desencriptado.IndexOf(_namespace) - 3;
        //    char c = desencriptado[final];

        //    while (c != ':')
        //    {
        //        prefix = c + prefix;
        //        final--;
        //        c = desencriptado[final];
        //    }
        //    return prefix;
        //}
        public int getBadCharCount(string desencriptado)
        {
            int final = desencriptado.Length - 1;
            char c = desencriptado[final];
            char c1 = desencriptado[final - 1];
            int count = 0;
            while (c != '>' && c1 != 'e')
            {
                final--;
                c = desencriptado[final];
                c1 = desencriptado[final - 1];
                count++;
            }
            return count;
        }
        public string getAction(int inicio, string desencriptado)
        {

            string _namespace = namespaces["valid"];

            if (!desencriptado.Contains(_namespace))
            {
                _namespace = namespaces["invalid"];
                if (!desencriptado.Contains(_namespace))
                    return "";
            }
            string action = "";
            while (desencriptado[inicio] != ':')
                inicio++;
            inicio++;
            while (desencriptado[inicio] != ' ')
                action += desencriptado[inicio++];
            return _namespace + action;
        }
        public override Message ReadMessage(Stream stream, int maxSizeOfHeaders, string contentType)
        {

            return innerEncoder?.ReadMessage(stream, maxSizeOfHeaders, contentType);
        }
        private int getInicio(string desencriptado)
        {
            string _namespace = namespaces["valid"];

            if (!desencriptado.Contains(_namespace))
            {
                _namespace = namespaces["invalid"];
                if (!desencriptado.Contains(_namespace))
                    return -1;
            }

            int final = desencriptado.IndexOf(_namespace) - 3;
            char c = desencriptado[final];

            while (c != '<')
            {
                final--;
                c = desencriptado[final];
            }
            return final;
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



        public static bool Verify(XmlDocument document)
        {

            SignedXmlWithId signed = new SignedXmlWithId(document);
            XmlNodeList list = document.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#");
            XmlNodeList BinarySecurityTokens = document.DocumentElement.SelectNodes("//*[local-name()='BinarySecurityToken']");

            var valueCertificate = BinarySecurityTokens[0].InnerText;


            X509Certificate2 dcert2 = new X509Certificate2(Convert.FromBase64String(valueCertificate));


            if (list == null)
                throw new CryptographicException($"The XML document has no signature.");
            if (list.Count > 1)
                throw new CryptographicException($"The XML document has more than one signature.");

            signed.LoadXml((XmlElement)list[0]);

            RSA rsa = null;
            //foreach (KeyInfoClause clause in signed.KeyInfo)
            //{
            RSAKeyValue value = null;//clause as RSAKeyValue;

            //if (value == null)
            //{
            RSACryptoServiceProvider rsaprovider = (RSACryptoServiceProvider)dcert2.PublicKey.Key;
            value = new RSAKeyValue(rsaprovider);
            signed.KeyInfo.AddClause(value);
            //}

            RSAKeyValue key = value;
            rsa = key.Key;
            //}

            bool result = rsa != null && signed.CheckSignature(dcert2, true);
            return result;
        }

    }
}
