using ComponentPro.Saml2;
using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.ServiceModel.Security;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace MySecurityBE.Saml2
{
    public class SamlAssertionSecurityTokenSerializer : WSSecurityTokenSerializer
    {

        private const string strxmlns = "xmlns";
        private const string strwssens = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        private const string strwsse = "wsse";
        private const string strwssu = "wsu";


        private static bool CorrioSaml = false;
        public SamlAssertionSecurityTokenSerializer(SecurityTokenVersion version) : base() { }

        protected override bool CanReadTokenCore(XmlReader reader)
        {
            XmlDictionaryReader localReader = XmlDictionaryReader.CreateDictionaryReader(reader);
            if (reader == null)
            {
                throw new ArgumentNullException("reader");
            }
            return base.CanReadTokenCore(reader);
        }

        protected override SecurityToken ReadTokenCore(XmlReader reader, SecurityTokenResolver tokenResolver)
        {
            if (reader == null)
            {
                throw new ArgumentNullException("reader");
            }
            if (reader.IsStartElement("Assertion", "urn:oasis:names:tc:SAML:2.0:assertion"))
            {
                string assertion = reader.ReadOuterXml();
                Assertion samlAssertion = new Assertion(assertion);
                SamlAssertionInfo info = new SamlAssertionInfo(samlAssertion);
                return new SamlToken(info, samlAssertion.Id);
            }
            else
            {
                return base.ReadTokenCore(reader, tokenResolver);
            }
        }

        protected override bool CanWriteTokenCore(SecurityToken token)
        {
            if (token is SamlToken)
            {
                return true;
            }
            else
            {
                return base.CanWriteTokenCore(token);
            }
        }

        protected override void WriteTokenCore(XmlWriter writer, SecurityToken token)
        {
            if (writer == null)
            {
                throw new ArgumentNullException("writer");
            }
            if (token == null)
            {
                throw new ArgumentNullException("token");
            }

            SamlToken c = token as SamlToken;
            if (c != null)
            {
                //Saml-----------------------------------
                c.SamlAssertionInfo.SamlAssertion.Id = token.Id;
                XmlElement assertion = c.SamlAssertionInfo.SamlAssertion.GetXml();
                assertion.WriteTo(writer);
                CorrioSaml = true;
            }
            else
                base.WriteTokenCore(writer, token);
        }



    }
}
