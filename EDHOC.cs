using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Com.AugustCellars.COSE;
using PeterO.Cbor;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Modes.Gcm;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;


namespace EDHOC
{
    public class EDHOC
    {
        Boolean _fSymmetricSecret = false;
        CBORObject[] _kid = new CBORObject[2];
        byte[][] _SessionId = new byte[2][];
        byte[][] _Nonce = new byte[2][];
        OneKey[] _Keys = new OneKey[2];
        CBORObject _algKeyAgree;
        CBORObject _algAEAD;
        CBORObject _algSign;
        byte[][] _Messages = new byte[3][];

        OneKey _Secret;
        OneKey _SigningKey;

        static Dictionary<byte[], EDHOC> MessageList = new Dictionary<byte[], EDHOC>(); 
        

        public byte[] KeyIdentifier {
            get { return _kid[1].GetByteString(); }
        }

        byte[] _SharedSecret;
        public byte[] SharedSecret {
            get { return _SharedSecret; }
            set { _SharedSecret = value; }
        }

        public OneKey SigningKey {
            get { return _SigningKey; }
            set { _SigningKey = value; }
        }

        private EDHOC()
        {
            ;
        }

        /// <summary>
        /// Create an EDHOC context for a suplicant to generate messages from.
        /// </summary>
        /// <param name="contextKey">Either shared secret or signing to key to used to do identity proofing for</param>
        public EDHOC(OneKey contextKey)
        {
            switch ((GeneralValuesInt) contextKey[CoseKeyKeys.KeyType].AsInt32()) {
                case GeneralValuesInt.KeyType_Octet:
                    _fSymmetricSecret = true;
                    break;

                case GeneralValuesInt.KeyType_EC2:
                case GeneralValuesInt.KeyType_OKP:
                    _fSymmetricSecret = false;
                    if (!contextKey.ContainsName(CoseKeyParameterKeys.EC_D)) {
                        throw new Exception("Need to supply a private key with the signing key");
                    }
                    break;

                default:
                    throw new Exception("Unknown key type for secret");
            }

            _kid[0] = contextKey[CoseKeyKeys.KeyIdentifier];
            _SessionId[0] = UTF8Encoding.UTF8.GetBytes("Session ID");
            _Nonce[0] = UTF8Encoding.UTF8.GetBytes("Nonce Client");
            _Keys[0] = OneKey.GenerateKey(null, GeneralValues.KeyType_OKP, "Ed25519");

            
            _Secret = contextKey;
        }

        public byte[] CreateMessage1()
        {
            CBORObject msg = CBORObject.NewArray();
            if (_fSymmetricSecret) {
                msg.Add(4);
            }
            else {
                msg.Add(1);                                 // Msg Type
            }

            msg.Add(_SessionId[0]);
            msg.Add(_Nonce[0]);
            msg.Add(_Keys[0]);

            CBORObject obj = CBORObject.NewArray();         // Key Agree algorithms
            obj.Add(AlgorithmValues.ECDH_SS_HKDF_256);
            msg.Add(obj);

            obj = CBORObject.NewArray();
            obj.Add(AlgorithmValues.AES_CCM_64_64_128);     // AEAD algorithms
            msg.Add(obj);

            if (_fSymmetricSecret) {
                msg.Add("KID");
            }
            else {
                obj = CBORObject.NewArray();                // SIG verify algorithms
                obj.Add(AlgorithmValues.EdDSA);
                msg.Add(obj);

                msg.Add(obj);                               // SIG generate algorithms
            }

            MessageList.Add(_SessionId[0], this);

            _Messages[0] = msg.EncodeToBytes();         // message_1
            return _Messages[0];
        }

        static public EDHOC ParseMessage1(byte[] msgData)
        {
            EDHOC edhoc = new EDHOC();
            CBORObject msg = CBORObject.DecodeFromBytes(msgData);
            if (msg.Type != CBORType.Array) throw new Exception("Invalid message");
            if (msg[0].AsInt32() == 1) {
                edhoc._fSymmetricSecret = false;
            }
            else if (msg[0].AsInt32() == 4) {
                edhoc._fSymmetricSecret = true;

            }
            else throw new Exception("Invalid Message");

            edhoc._Messages[0] = msgData;               // message_1

            edhoc._SessionId[1] = msg[1].GetByteString();
            edhoc._Nonce[1] = msg[2].GetByteString();
            edhoc._Keys[1] = new OneKey(msg[3]);
            edhoc._algKeyAgree = _SelectAlgorithm(msg[4], AlgorithmValues.ECDH_SS_HKDF_256);
            edhoc._algAEAD = _SelectAlgorithm(msg[5], AlgorithmValues.AES_CCM_64_64_128);
            edhoc._algSign = _SelectAlgorithm(msg[6], AlgorithmValues.EdDSA);

            edhoc._Keys[0] = OneKey.GenerateKey(null, edhoc._Keys[1][CoseKeyKeys.KeyType], edhoc._Keys[1][CoseKeyParameterKeys.EC_Curve].AsString());
            edhoc._SessionId[0] = edhoc._SessionId[1];
            edhoc._Nonce[0] = UTF8Encoding.UTF8.GetBytes("Server Nonce");

            MessageList.Add(edhoc._SessionId[0], edhoc);

            return edhoc;
        }

        public byte[] CreateMessage2()
        {
            CBORObject msg = CBORObject.NewArray();
            CBORObject obj;

            if (_fSymmetricSecret) {
                msg.Add(5);             // Msg Type
            }
            else {
                msg.Add(2);
            }

            msg.Add(_SessionId[1]);     // S_U
            msg.Add(_SessionId[0]);     // S_V
            msg.Add(_Nonce[0]);         // N_V
            msg.Add(_Keys[0]);          // E_V
            msg.Add(_algKeyAgree);      // HKDF_V
            msg.Add(_algAEAD);          // AEAD_V
            if (!_fSymmetricSecret) {
                msg.Add(_algSign);          // SIG_V

                obj = CBORObject.NewArray();
                obj.Add(AlgorithmValues.EdDSA);
                msg.Add(obj);               // SIGs_V
            }

            byte[] data2 = msg.EncodeToBytes();
            byte[] aad_2 = Concatenate(new byte[2][] { _Messages[0], data2 });   // M00TODO - hash message[0] before passing it in.

            byte[][] useKeys = _DeriveKeys(_Keys, null, aad_2, _algAEAD.AsInt32());
            byte[] aeadKey = useKeys[0];

            Sign1Message sign1 = new Sign1Message(false, false);
            sign1.SetContent(aad_2);
            sign1.AddAttribute(HeaderKeys.KeyId, _Secret[CoseKeyKeys.KeyIdentifier], Attributes.UNPROTECTED);

            sign1.Sign(_Secret);
            byte[] signResult = sign1.EncodeToBytes();

            Encrypt0Message enc0 = new Encrypt0Message(true);
            enc0.AddAttribute(HeaderKeys.Algorithm, _algAEAD, Attributes.DO_NOT_SEND);
            enc0.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(useKeys[1]), Attributes.DO_NOT_SEND);
            enc0.SetExternalData(aad_2);
            CBORObject encContent = CBORObject.NewArray();
            encContent.Add(signResult);
            enc0.SetContent(encContent.EncodeToBytes());

            enc0.Encrypt(aeadKey);
            msg.Add(enc0.EncodeToCBORObject());  // COSE_ENC_2

            _Messages[1] = msg.EncodeToBytes();
            return _Messages[1];
        }

        static public EDHOC ParseMessage2(byte[] msgData, KeySet keySetPublic)
        {
            EDHOC edhoc;
            int msgIndex;
            CBORObject algVerify = null;

            CBORObject msg = CBORObject.DecodeFromBytes(msgData);
            if (msg.Type != CBORType.Array) throw new Exception("Invalid message");

            edhoc = MessageList[msg[1].GetByteString()];  // Lookup by S_U

            edhoc._Messages[1] = msgData;

            if (edhoc._fSymmetricSecret) {
                if (msg[0].AsInt16() != 5) throw new Exception("Invalid Message");
            }
            else {
                if (msg[0].AsInt16() != 2) throw new Exception("Invalid Message");
            }

            edhoc._SessionId[1] = msg[2].GetByteString();       // S_V
            edhoc._Nonce[1] = msg[3].GetByteString();           // N_V
            edhoc._Keys[1] = new OneKey(msg[4]);                // E_V
            edhoc._algKeyAgree = msg[5];                        // HKDF_V
            edhoc._algAEAD = msg[6];                            // AAEAD_V
            if (edhoc._fSymmetricSecret) {
                msgIndex = 7;
            }
            else {
                algVerify = msg[7];                             // SIG_V
                edhoc._algSign = msg[8];                        // SIG_U
                msgIndex = 9;
            }


            Encrypt0Message enc0 = (Encrypt0Message)Message.DecodeFromBytes(msg[msgIndex].EncodeToBytes(), Tags.Encrypt0);

            msg.Remove(msg[msgIndex]);
            byte[] data_2 = msg.EncodeToBytes();
            byte[] aad_2 = new byte[edhoc._Messages[0].Length + data_2.Length];  // M00TODO - hash Message1 before doing this.

            byte[][] useKeys = _DeriveKeys(edhoc._Keys, null, aad_2, edhoc._algAEAD.AsInt32());
            byte[] encKey = useKeys[0];
            enc0.AddAttribute(HeaderKeys.Algorithm, edhoc._algAEAD, Attributes.DO_NOT_SEND);
            enc0.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(useKeys[1]), Attributes.DO_NOT_SEND);
            byte[] body = enc0.Decrypt(encKey);

            if (!edhoc._fSymmetricSecret) {
                CBORObject encBody = CBORObject.DecodeFromBytes(body);

                Sign1Message sign1 = (Sign1Message)Message.DecodeFromBytes(encBody[0].EncodeToBytes(), Tags.Sign1);
                sign1.AddAttribute(HeaderKeys.Algorithm, algVerify, Attributes.DO_NOT_SEND);

                CBORObject kid = sign1.FindAttribute(HeaderKeys.KeyId);
                sign1.SetExternalData(aad_2);


                foreach (OneKey sigKey in keySetPublic) {

                    sign1.Validate(sigKey); //FIND KEY);
                }
            }
            else {
                // body is the EXT_2 value
            }


            return edhoc;
        }

        public byte[] CreateMessage3()
        {
            CBORObject msg = CBORObject.NewArray();

            if (_fSymmetricSecret) {
                msg.Add(6);
            }
            else {
                msg.Add(3);
            }
            msg.Add(_SessionId[0]);

            byte[] aad_3 = Concatenate(new byte[3][] { _Messages[0], _Messages[1], msg.EncodeToBytes() });  //M00BUG this is an incorrect formula

            Sign1Message sign1 = new Sign1Message(false, false);
            sign1.SetContent(aad_3);
            sign1.AddAttribute(HeaderKeys.Algorithm, _algSign, Attributes.DO_NOT_SEND);
            sign1.AddAttribute(HeaderKeys.KeyId, _Secret[CoseKeyKeys.KeyIdentifier], Attributes.UNPROTECTED);
            sign1.Sign(_Secret);

            CBORObject obj = CBORObject.NewArray();
            obj.Add(sign1.BEncodeToBytes());

            byte[][] encKeys = _DeriveKeys(_Keys, null, aad_3, _algAEAD.AsInt32());

            Encrypt0Message enc = new Encrypt0Message(false);
            enc.SetExternalData(aad_3);
            enc.AddAttribute(HeaderKeys.Algorithm, _algAEAD, Attributes.DO_NOT_SEND);
            enc.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(encKeys[1]), Attributes.DO_NOT_SEND);
            enc.Encrypt(encKeys[0]);

            msg.Add(enc.EncodeToBytes());

            return msg.EncodeToBytes();
        }

        static public EDHOC ParseMessage3(byte[] msgData, KeySet serverKeys)
        {
            EDHOC edhoc;
            int msgIndex;
            CBORObject algVerify = null;

            CBORObject msg = CBORObject.DecodeFromBytes(msgData);
            if (msg.Type != CBORType.Array) throw new Exception("Invalid message");

            edhoc = MessageList[msg[1].GetByteString()];  // Lookup by S_V

            edhoc._Messages[2] = msgData;

            if (edhoc._fSymmetricSecret) {
                if (msg[0].AsInt16() != 6) throw new Exception("Invalid Message");
            }
            else {
                if (msg[0].AsInt16() != 3) throw new Exception("Invalid Message");
            }


            Encrypt0Message enc0 = (Encrypt0Message)Message.DecodeFromBytes(msg[2].EncodeToBytes(), Tags.Encrypt0);

            msg.Remove(msg[2]);

            byte[] data_3 = msg.EncodeToBytes();
            byte[] aad_3 = new byte[edhoc._Messages[0].Length + data_3.Length];  // M00TODO - hash Message1 before doing this.

            byte[][] useKeys = _DeriveKeys(edhoc._Keys, null, aad_3, edhoc._algAEAD.AsInt32());
            byte[] encKey = useKeys[0];

            enc0.AddAttribute(HeaderKeys.Algorithm, edhoc._algAEAD, Attributes.DO_NOT_SEND);
            enc0.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(useKeys[1]), Attributes.DO_NOT_SEND);
            byte[] body = enc0.Decrypt(encKey);

            if (!edhoc._fSymmetricSecret) {
                CBORObject encBody = CBORObject.DecodeFromBytes(body);

                Sign1Message sign1 = (Sign1Message)Message.DecodeFromBytes(encBody[0].EncodeToBytes(), Tags.Sign1);
                sign1.AddAttribute(HeaderKeys.Algorithm, algVerify, Attributes.DO_NOT_SEND);

                CBORObject kid = sign1.FindAttribute(HeaderKeys.KeyId);
                sign1.SetExternalData(aad_3);


                foreach (OneKey sigKey in serverKeys) {

                    sign1.Validate(sigKey); //FIND KEY);
                }
            }
            else {
                // body is the EXT_3 value
            }


            return edhoc;
        }

        /// <summary>
        /// Compute and derive the keys based on the input data
        /// </summary>
        /// <param name="keys">Public and Private DH keys to use for creating shared secret</param>
        /// <param name="salt">A shared symmetric key if one exists</param>
        /// <param name="otherData">SuppPubInfo other data bytes - changes for each message</param>
        /// <param name="algAEAD">Symmetric algorithm for encryption</param>
        /// <returns>array of two byte arrays.  The first is the key, the second is the IV</returns>
        private static byte[][] _DeriveKeys(OneKey[] keys, byte[] salt, byte[] otherData, int algAEAD)
        {
            int cbitKey = 0;
            int cbitIV = 0;

            byte[] secret = ECDH_GenerateSecret(keys);

            switch ((AlgorithmValuesInt) algAEAD) {
                case AlgorithmValuesInt.AES_CCM_64_64_128:
                    cbitKey = 128;
                    cbitIV = 64;
                    break;

                default:
                    throw new Exception("Unknown Algorithm");
                    
            }

            CBORObject partyInfo;
            partyInfo = CBORObject.NewArray();
            partyInfo.Add(CBORObject.Null);
            partyInfo.Add(CBORObject.Null);
            partyInfo.Add(CBORObject.Null);

            CBORObject context = CBORObject.NewArray();
            context.Add(algAEAD);       // Alg
            context.Add(partyInfo);     // Party U
            context.Add(partyInfo);     // Party V

            CBORObject obj = CBORObject.NewArray();
            obj.Add(cbitKey);
            obj.Add(CBORObject.FromObject(new byte[0]));
            obj.Add(otherData);
            context.Add(obj);           // SuppPubInfo

            byte[] rgbContext = context.EncodeToBytes();

            byte[][] returnValue = new byte[2][];

            returnValue[0] = HKDF(secret, salt, rgbContext, cbitKey, new Sha256Digest());

            obj[0] = CBORObject.FromObject(cbitIV);
            context[0] = CBORObject.FromObject("EDHOC IV");
            returnValue[1] = HKDF(null, secret, rgbContext, cbitIV, new Sha256Digest());
            return returnValue;
        }

        private static CBORObject _SelectAlgorithm(CBORObject algList, CBORObject alg)
        {
            // M00BUG Not correct impementation.
            if (algList.Count == 1) return algList[0];
            return algList[0];
        }

        static private byte[] Concatenate(byte[][] arrays)
        {
            byte[] rv = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;
            foreach (byte[] array in arrays) {
                System.Buffer.BlockCopy(array, 0, rv, offset, array.Length);
                offset += array.Length;
            }
            return rv;
        }

        private static byte[] ECDH_GenerateSecret(OneKey[] keys)
        {
            if (keys[0][CoseKeyKeys.KeyType].Type != CBORType.Number) throw new CoseException("Not an EC Key");
            if (keys[1][CoseKeyKeys.KeyType].Type != CBORType.Number) throw new CoseException("Not an EC Key");

            OneKey epkPub = keys[1];
            OneKey epkPriv = keys[0];

            byte[] temp;

            switch ((GeneralValuesInt)epkPub[CoseKeyKeys.KeyType].AsInt32()) {
                case GeneralValuesInt.KeyType_OKP:
                    if (epkPub[CoseKeyParameterKeys.OKP_Curve].AsInt32() != epkPriv[CoseKeyParameterKeys.OKP_Curve].AsInt32()) throw new CoseException("Not a match of curves");

                    switch ((GeneralValuesInt)epkPriv[CoseKeyParameterKeys.OKP_Curve].AsInt32()) {
                        case GeneralValuesInt.X25519:
                            temp = X25519.CalculateAgreement(epkPub.AsBytes(CoseKeyParameterKeys.OKP_X), epkPriv.AsBytes(CoseKeyParameterKeys.OKP_D));
                            break;

                        default:
                            throw new CoseException("Not a supported Curve");
                    }
                    return temp;

                case GeneralValuesInt.KeyType_EC2:

                    if (epkPub[CoseKeyParameterKeys.EC_Curve].AsInt32() != epkPriv[CoseKeyParameterKeys.EC_Curve].AsInt32()) throw new CoseException("not a match of curves");

                    //  Get the curve

                    X9ECParameters p = epkPub.GetCurve();
                    ECPoint pubPoint = epkPub.GetPoint();

                    ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);

                    ECPublicKeyParameters pub = new ECPublicKeyParameters(pubPoint, parameters);

                    ECPrivateKeyParameters priv = new ECPrivateKeyParameters(epkPriv.AsBigInteger(CoseKeyParameterKeys.EC_D), parameters);

                    IBasicAgreement e1 = new ECDHBasicAgreement();
                    e1.Init(priv);

                    BigInteger k1 = e1.CalculateAgreement(pub);

                    
                    return PadBytes(k1.ToByteArrayUnsigned(), p.Curve.FieldSize);

                default:
                    throw new CoseException("Not an EC Key");
            }
        }

        static private byte[] PadBytes(byte[] rgbIn, int outSize)
        {
            outSize = (outSize + 7) / 8;
            if (rgbIn.Length == outSize) return rgbIn;
            byte[] x = new byte[outSize];
            Array.Copy(rgbIn, 0, x, outSize - rgbIn.Length, rgbIn.Length);
            return x;
        }

        private static byte[] HKDF(byte[] secret, byte[] salt, byte[] info, int cbit, IDigest digest)
        {
            //  Now start doing HKDF
            //  Perform the Extract phase
            HMac mac = new HMac(digest);

            int hashLength = digest.GetDigestSize();
            int c = ((cbit + 7) / 8 + hashLength - 1) / hashLength;

            if (salt == null) salt = new byte[0];
            KeyParameter key = new KeyParameter(salt);
            mac.Init(key);
            mac.BlockUpdate(secret, 0, secret.Length);

            byte[] rgbExtract = new byte[hashLength];
            mac.DoFinal(rgbExtract, 0);


            //  Now do the Expand Phase

            byte[] rgbOut = new byte[cbit / 8];
            byte[] rgbT = new byte[hashLength * c];
            mac = new HMac(digest);
            key = new KeyParameter(rgbExtract);
            mac.Init(key);
            byte[] rgbLast = new byte[0];
            byte[] rgbHash2 = new byte[hashLength];

            for (int i = 0; i < c; i++) {
                mac.Reset();
                mac.BlockUpdate(rgbLast, 0, rgbLast.Length);
                mac.BlockUpdate(info, 0, info.Length);
                mac.Update((byte)(i + 1));

                rgbLast = rgbHash2;
                mac.DoFinal(rgbLast, 0);
                Array.Copy(rgbLast, 0, rgbT, i * hashLength, hashLength);
            }

            Array.Copy(rgbT, 0, rgbOut, 0, cbit / 8);
            return rgbOut;
        }
    }
}
