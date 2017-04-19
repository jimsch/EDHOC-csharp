using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PeterO.Cbor;

using Com.AugustCellars.COSE;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Server;
using Com.AugustCellars.CoAP.EDHOC;
using Com.AugustCellars.CoAP.OSCOAP;

namespace Server
{
    class Program
    {
        readonly static CBORObject usageKey = CBORObject.FromObject("usage");

        static bool IsSigner(OneKey key)
        {
            if (key[usageKey].AsString().Contains("EDHOC")) {
                if (key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_EC) &&
                    key.ContainsName(CoseKeyParameterKeys.EC_D)) {
                    return true;
                }
                if (key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_OKP) &&
                    key.ContainsName(CoseKeyParameterKeys.OKP_D)) {
                    return true;
                }
            }
            return false;
        }

        static bool IsEdhocPublic(OneKey key)
        {
            if (key[usageKey].AsString().Contains("EDHOC")) {
                if (key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_EC) &&
                    key.ContainsName(CoseKeyParameterKeys.EC_D)) {
                    return false;
                }
                if (key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_OKP) &&
                    key.ContainsName(CoseKeyParameterKeys.OKP_D)) {
                    return false;
                }
                return true;
            }
            return false;
        }

        static void Main(string[] args)
        {
            CoapServer server = new CoapServer();

            KeySet allKeys = LoadKeys(null);

            KeySet signingKeys = allKeys.Where(IsSigner);
            KeySet publicKeys = allKeys.Where(IsEdhocPublic);
            OneKey signKey = null;
            foreach (OneKey key in signingKeys) {
                signKey = key;
                break;
            }

            server.Add(new EdhocResource(publicKeys, signKey));

            server.Start();

            Console.WriteLine("Press key to exit");
            Console.ReadKey();
        }

        static KeySet LoadKeys(string fileName)
        {
            if (fileName == null)
                fileName = "ServerKeys.cbor";
            KeySet keys = new KeySet();

            FileStream fs = new FileStream(fileName, FileMode.Open);
            using (BinaryReader reader = new BinaryReader(fs)) {
                byte[] data = reader.ReadBytes((int) fs.Length);
                CBORObject obj = CBORObject.DecodeFromBytes(data);
                for (int i = 0; i < obj.Count; i++) {
                    OneKey key = new OneKey(obj[i]);
                    string[] usages = key[usageKey].AsString().Split(' ');

                    foreach (String usage in usages) {
                        if (usage == "oscoap") {
                            SecurityContext ctx = SecurityContext.DeriveContext(
                                key[CoseKeyParameterKeys.Octet_k].GetByteString(),
                                key[CBORObject.FromObject("RecipID")].GetByteString(),
                                key[CBORObject.FromObject("SenderID")].GetByteString(), null,
                                key[CoseKeyKeys.Algorithm]);
                            SecurityContextSet.AllContexts.Add(ctx);
                            break;
                        }
                    }

                    if ((usages.Length != 1) || (usages[0] != "oscoap")) {
                        keys.AddKey(key);
                    }
                }
                reader.Close();
            }
            return keys;
        }

    }
}
