using System;
using NUnit.Framework;
using Com.AugustCellars.COSE;
using Com.AugustCellars.CoAP.EDHOC;
using PeterO.Cbor;

namespace Com.AugustCellars.CoAP.EDHOC.Test
{
    [TestFixture]
    public class EdhocInitiator_Test
    {
        OneKey keyDSA;
        OneKey keyEdDSA;
        OneKey keyOctet;
        byte[] octetKeyValue;
        byte[] octetKeyID;

        [OneTimeSetUp]
        public void Setup()
        {
            keyOctet=new OneKey();
            keyOctet.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_Octet);
            keyOctet.Add(CoseKeyParameterKeys.Octet_k, CBORObject.FromObject(octetKeyValue));
            keyOctet.Add(CoseKeyKeys.KeyIdentifier, CBORObject.FromObject(octetKeyID));

            keyEdDSA = OneKey.GenerateKey(null, GeneralValues.KeyType_EC, "P-256");
            keyDSA = OneKey.GenerateKey(null, GeneralValues.KeyType_OKP, "Ed25519");
        }

        [Test]
        public void Create_Test1()
        {
            Exception e = Assert.Throws<NullReferenceException>(() => new EdhocInitiator(null));
        }

        [Test]
        public void Create_Test2()
        {
            OneKey key = new OneKey();
            key.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_RSA);

            Exception e = Assert.Throws<Exception>(() => new EdhocInitiator(key));
            Assert.That(e.Message, Is.EqualTo("Unknown key type for secret"));
;        }

        [Test]
        public void Create_Test3()
        {
            Exception e = Assert.Throws<Exception>(() => new EdhocInitiator(keyDSA.PublicKey()));
            Assert.That(e.Message, Is.EqualTo("Need to supply a private key with the signing key"));

        }

        [Test]
        public void Create_Test4()
        {
            Exception e = Assert.Throws<Exception>(() => new EdhocInitiator(keyEdDSA.PublicKey()));
            Assert.That(e.Message, Is.EqualTo("Need to supply a private key with the signing key"));

        }

        [Test]
        public void CreateMessage1_1()
        {
            EdhocInitiator e = new EdhocInitiator(keyOctet);

            byte[] val = e.CreateMessage1();
            Assert.That(val, !Is.EqualTo(null));
            CBORObject obj = CBORObject.DecodeFromBytes(val);
            Assert.That(obj.Type, Is.EqualTo(CBORType.Array));
            Assert.That(obj.Count, Is.EqualTo(7));

        }
    }
}
