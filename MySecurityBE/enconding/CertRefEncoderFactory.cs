using System;
using System.ServiceModel.Channels;

namespace CertFixEscapedComma
{
    public class CertRefEncoderFactory : MessageEncoderFactory
    {
        private MessageEncoderFactory innerFactory;
        CertRefEncoder enc;

        public CertRefEncoderFactory(MessageEncoderFactory innerFactory)
        {
            this.innerFactory = innerFactory;
            if (innerFactory == null)
                throw new ArgumentNullException("innerFactory");
            enc = new CertRefEncoder(innerFactory.Encoder);
        }
        public override MessageEncoder Encoder
        {
            get { return enc; }
        }

        public override MessageVersion MessageVersion
        {
            get { return this.innerFactory.MessageVersion; }
        }

        public override MessageEncoder CreateSessionEncoder()
        {
            return this.enc;
        }
    }
}
