using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using NUnit.Framework;

using PeterO.Cbor;
using Com.AugustCellars.COSE;

using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Net;
using Com.AugustCellars.CoAP.Server;
using Com.AugustCellars.CoAP.Server.Resources;

using Com.AugustCellars.CoAP.EDHOC;

namespace Com.AugustCellars.CoAP.EDHOC.Test
{
    [TestFixture]
    class Scenerios
    {
        private int _serverPort;
        private CoapServer _server;
        private Resource _resource;
        private OneKey psk;
        private OneKey serverSignKey;


        [SetUp]
        public void SetupServer()
        {
            serverSignKey = OneKey.GenerateKey(null, GeneralValues.KeyType_OKP);
            CreateServer();

            psk = new OneKey();
            psk.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_Octet);
            psk.Add(CoseKeyKeys.KeyIdentifier, CBORObject.FromObject(new byte[3] { 1, 2, 3 }));
            psk.Add(CoseKeyParameterKeys.Octet_k, CBORObject.FromObject(new byte[16] { 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}));
        }

        [TearDown]
        public void ShutdownServer()
        {
            _server.Dispose();
        }

        [Test]
        public void TestSharedSecret()
        {
            Request req;
            Uri uriHello = new Uri("coap://localhost:" + _serverPort + "/hello");
            Uri uri = new Uri("coap://localhost:" + _serverPort + "/" + "edhoc");
            CoapClient clientHello = new CoapClient(uriHello);
            CoapClient client = new CoapClient(uri);

            //  Try and get hello -- should fail because no security setup.

            CoAP.Response resp = clientHello.Get();
            Assert.AreEqual(CoAP.StatusCode.Forbidden, resp.StatusCode);

            //  Create and send message #1 for PSK

            EDHOC.EdhocInitiator init = new EdhocInitiator(psk);
            byte[] msg = init.CreateMessage1();

            req = new Request(Method.PUT);
            req.Payload = msg;
            resp = client.Send(req);
            Assert.AreEqual(CoAP.StatusCode.Changed, resp.StatusCode);

            //  Process response message

            KeySet ks = new KeySet();
            ks.AddKey(serverSignKey);
            init.ParseMessage2(resp.Payload, ks);

            //  Setup my security context.
            OSCOAP.SecurityContext ctx = init.CreateSecurityContext();

            req = new Request(Method.GET);
            req.URI = uriHello;
            req.OscoapContext = ctx;
            resp = clientHello.Send(req);

            Assert.AreEqual(StatusCode.Content, resp.StatusCode);

        }

        private void CreateServer()
        {
            CoAPEndPoint endpoint = new CoAPEndPoint(0);
            _resource = new EdhocResource(null, null);
            _server = new CoapServer();
            _server.Add(_resource);

            _server.AddEndPoint(endpoint);
            _server.Start();
            _serverPort = ((System.Net.IPEndPoint) endpoint.LocalEndPoint).Port;
        }
    }
}
