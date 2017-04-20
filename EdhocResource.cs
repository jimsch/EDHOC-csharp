using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Com.AugustCellars.COSE;
using Com.AugustCellars.CoAP.Server.Resources;
using PeterO.Cbor;

namespace Com.AugustCellars.CoAP.EDHOC
{
    public class EdhocResource : Resource
    {
        Dictionary<byte[], EdhocResponder> currentSetOfItems = new Dictionary<byte[], EdhocResponder>();
        KeySet _allKeys;
        OneKey _signKey;

        public EdhocResource(KeySet allKeys, OneKey signingKey) : base("edhoc")
        {
            _allKeys = allKeys;
            _signKey = signingKey;
        }

        public KeySet AllKeys {
            get { return _allKeys; }
            set { _allKeys = value; }
        }
        public OneKey SigningKey {
            get { return _signKey; }
            set { _signKey = value; }
        }

        protected override void DoPost(CoapExchange exchange)
        {
            byte[] body = exchange.Request.Payload;
            EdhocResponder edhoc;

            try {
                switch (body[1] & 0xf) {
                    case 1:
                        edhoc = EdhocResponder.ParseMessage1(body);
                        edhoc.SigningKey = _signKey;
                        body = edhoc.CreateMessage2();
                        exchange.Respond(CoAP.StatusCode.Changed, body);
                        break;

                    case 4:
                        edhoc = EdhocResponder.ParseMessage1(body);
                        OneKey y = null;
                        foreach (Key x in _allKeys) {
                            if (x.ContainsName(CoseKeyKeys.KeyIdentifier)) {
                                if (x[CoseKeyKeys.KeyIdentifier].GetByteString().Equals(edhoc.KeyIdentifier)) {
                                    if (y != null) {
                                        exchange.Respond(CoAP.StatusCode.BadRequest);
                                        return;
                                    }
                                    y = new OneKey(x.AsCBOR());
                                }
                            }
                        }
                        if (y == null) {
                            exchange.Respond(CoAP.StatusCode.BadRequest);
                            return;
                        }

                        if (!y[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_Octet)) {
                            exchange.Respond(CoAP.StatusCode.BadRequest);
                            return;
                        }

                        edhoc.SharedSecret = y;

                        body = edhoc.CreateMessage2();
                        exchange.Respond(CoAP.StatusCode.Changed, body);
                        break;

                    case 3:
                        edhoc = EdhocResponder.ParseMessage3(body, _allKeys);

                        // CoAP.OSCOAP.SecurityContext ctx = CoAP.OSCOAP.SecurityContext.DeriveContext(edhoc.MasterSecret, SenderId, Recipientid, null, edhoc.AlgAEAD);
                        // CoAP.OSCOAP.SecurityContextSet.AllContexts.Add(ctx);
                        break;

                    case 6:
                        edhoc = EdhocResponder.ParseMessage3(body, _allKeys);
                        break;

                    default:
                        exchange.Respond(CoAP.StatusCode.BadRequest);
                        break;
                }
            }
            catch (Exception e) {
                CBORObject obj = CBORObject.NewArray();
                obj.Add(0);
                obj.Add(e.ToString());
                exchange.Respond(CoAP.StatusCode.Content, obj.EncodeToBytes());
            }
        }
    }
}
