using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.Text;
using System.Xml;

namespace WpfApplication1.code.Inspector
{


    public class WSSecurity : MessageHeader
    {

        // the set of string const that is required for serialization.
        private const String strxmlns = "xmlns";
        private const String strwssens = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        private const String strwsse = "wsse";
        private const String strwssu = "wsu";


        public TimeSpan Created { get; set; }
        public TimeSpan Expires { get; set; }


        public override string Name
        {
            get
            {
                return "wsse:Security";
            }
        }

        public override string Namespace
        {
            get
            {
                return "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
            }
        }

        protected override void OnWriteHeaderContents(XmlDictionaryWriter writer, MessageVersion messageVersion)
        {
            writer.WriteAttributeString(strxmlns, strwsse, null, strwssens);
            writer.WriteAttributeString(strxmlns, strwssens);
            writer.WriteAttributeString(strxmlns, strwssu, null, strwssens);

            // <wsu:Timestamp>
            writer.WriteStartElement(strwssu, "TimeStamp", strwssens);
            writer.WriteAttributeString("wsu", "id", null, "TS-6E8683A796D1350D3A14670555706862");

            //<wsu:Created>
            writer.WriteStartElement(strwssu, "Created", strwssens);
            writer.WriteString(Created.ToString());
            writer.WriteEndElement();


            //<wsu:Expires>
            writer.WriteStartElement(strwssu, "Expires", strwssens);
            writer.WriteString(Expires.ToString());
            writer.WriteEndElement();


            writer.WriteEndElement();

            //ASSERTION SAML


        }
    }

    public class Inspector : IClientMessageInspector
    {
        public WSSecurity Security { get; set; }

        public void AfterReceiveReply(ref Message reply, object correlationState)
        {

        }

        public object BeforeSendRequest(ref Message request, IClientChannel channel)
        {
            //

            request.Headers.Add(Security);




            if (File.Exists("salida.txt"))
                File.Delete("salida.txt");


            File.WriteAllText("salida.txt", request.ToString());


            return null;

        }
    }

    public class BehaviorInspector : IEndpointBehavior
    {
        public Inspector Inspector { get; set; }

        public void AddBindingParameters(ServiceEndpoint endpoint, BindingParameterCollection bindingParameters)
        {
        }

        public void ApplyClientBehavior(ServiceEndpoint endpoint, ClientRuntime clientRuntime)
        {
            clientRuntime.MessageInspectors.Add(Inspector);
        }

        public void ApplyDispatchBehavior(ServiceEndpoint endpoint, EndpointDispatcher endpointDispatcher)
        {
        }

        public void Validate(ServiceEndpoint endpoint)
        {
        }
    }
}
