using System;
using System.Collections.Generic;
using System.Text;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Dispatcher;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.ServiceModel.Configuration;
using System.Xml;
using MySecurityBE.Saml2;

namespace MySecurityBE.Binding
{
    public class AsymetricSecurityBE : BindingElement
    {
        private AsymmetricSecurityBindingElement m_asymSecBE;
        public AsymetricSecurityBE()
        {
            m_asymSecBE = new AsymmetricSecurityBindingElement();
            m_asymSecBE.MessageSecurityVersion = MessageSecurityVersion.WSSecurity11WSTrustFebruary2005WSSecureConversationFebruary2005WSSecurityPolicy11BasicSecurityProfile10;
            m_asymSecBE.IncludeTimestamp = true;

            m_asymSecBE.SecurityHeaderLayout = SecurityHeaderLayout.Lax;

            m_asymSecBE.InitiatorTokenParameters = new X509SecurityTokenParameters()
            {
                InclusionMode = SecurityTokenInclusionMode.AlwaysToInitiator
            };
            m_asymSecBE.RecipientTokenParameters = new X509SecurityTokenParameters()
            {
                InclusionMode = SecurityTokenInclusionMode.AlwaysToInitiator,
                X509ReferenceStyle = X509KeyIdentifierClauseType.IssuerSerial
            };
            m_asymSecBE.DefaultAlgorithmSuite = SecurityAlgorithmSuite.Basic128;
            m_asymSecBE.MessageProtectionOrder = MessageProtectionOrder.SignBeforeEncrypt;
            m_asymSecBE.SetKeyDerivation(false);

            m_asymSecBE.AllowSerializedSigningTokenOnReply = false;
            m_asymSecBE.RequireSignatureConfirmation = false;
            m_asymSecBE.EndpointSupportingTokenParameters.SignedEncrypted.Add(new SamlAssertionTokenParameters());
            m_asymSecBE.ProtectTokens = true;

            m_asymSecBE.EnableUnsecuredResponse = true;
        }


        public AsymetricSecurityBE(AsymetricSecurityBE other)
        {
            m_asymSecBE = other.m_asymSecBE;
        }
        public override IChannelListener<TChannel> BuildChannelListener<TChannel>(BindingContext context)
        {
            return m_asymSecBE.BuildChannelListener<TChannel>(context);
        }
        public override IChannelFactory<TChannel> BuildChannelFactory<TChannel>(BindingContext context)
        {
            return m_asymSecBE.BuildChannelFactory<TChannel>(context);
        }
        public override BindingElement Clone()
        {
            AsymetricSecurityBE ret = new AsymetricSecurityBE(this);
            return ret;
        }
        public override T GetProperty<T>(BindingContext context)
        {
            return m_asymSecBE.GetProperty<T>(context);
        }
    }
    class AsymetricSecurityBEExtentionElement : BindingElementExtensionElement
    {
        public override Type BindingElementType
        {
            get { return typeof(AsymetricSecurityBE); }
        }

        protected override BindingElement CreateBindingElement()
        {
            return new AsymetricSecurityBE();
        }
    }
}
