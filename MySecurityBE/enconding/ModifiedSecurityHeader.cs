using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceModel.Channels;
using System.Xml;
using System.Diagnostics;

namespace CertFixEscapedComma
{
    public class ModifiedSecurityHeader : MessageHeader
    {
        private XmlDocument doc = new XmlDocument();

        public ModifiedSecurityHeader(XmlDocument dom)
        {
            doc = dom;
        }

        protected override void OnWriteHeaderContents(System.Xml.XmlDictionaryWriter writer, MessageVersion messageVersion)
        {
            doc.DocumentElement.WriteContentTo(writer);
        }

        protected override void OnWriteStartHeader(XmlDictionaryWriter writer, MessageVersion messageVersion)
        {
            writer.WriteStartElement(doc.DocumentElement.Prefix, doc.DocumentElement.LocalName, doc.DocumentElement.NamespaceURI);
            foreach (XmlAttribute attrib in doc.DocumentElement.Attributes)
            {
                attrib.WriteTo(writer);
            }
        }


        public override string Name
        {
            get { return doc.DocumentElement.LocalName; }
        }

        public override string Namespace
        {
            get { return doc.DocumentElement.NamespaceURI; }
        }
    }
}
