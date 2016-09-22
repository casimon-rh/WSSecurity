using System;
using System.ServiceModel.Channels;

namespace CertFixEscapedComma
{
    public class CertRefEncoderFactory : MessageEncoderFactory
    {
        private MessageEncoderFactory innerFactory;
        MessageEncoder enc;

        public CertRefEncoderFactory(MessageEncoderFactory innerFactory, MessageEncoder _enc)
        {
            this.innerFactory = innerFactory;
            if (innerFactory == null)
                throw new ArgumentNullException("innerFactory");
            enc = _enc;

            if (enc != null)
                enc.GetType().GetProperty("innerEncoder")?.SetValue(enc, innerFactory.Encoder);
            //enc = new CertRefEncoder(innerFactory.Encoder);
        }
        public override MessageEncoder Encoder
        {
            get { return enc; }
        }

        public override MessageVersion MessageVersion
        {
            get { return innerFactory?.MessageVersion; }
        }

        public override MessageEncoder CreateSessionEncoder()
        {
            return enc;
        }
    }
}
