using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace MySecurityBE.enconding
{
    public class SimpleMessageBody : BodyWriter
    {
        private string xmlContent;

        public SimpleMessageBody(string content)
           : base(true)
        {
            this.xmlContent = content;
        }
        protected override void OnWriteBodyContents(XmlDictionaryWriter writer)
        {
            using (StringReader stringReader = new StringReader(xmlContent))
            {
                using (XmlReader xmlReader = XmlTextReader.Create(stringReader))
                {
                    writer.WriteNode(xmlReader, true);
                }
            }
        }
    }
}
