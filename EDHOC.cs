using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Com.AugustCellars.COSE;
using Com.AugustCellars.CoAP;
using PeterO.Cbor;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;


namespace Com.AugustCellars.CoAP.EDHOC
{
    public class EdhocBase
    {
        protected class ListKey
        {
            private readonly byte[] _bytes;

            public ListKey(byte[] bytesIn)
            {
                if (bytesIn == null) throw new ArgumentException();
                _bytes = bytesIn;
            }

            public override bool Equals(object obj)
            {
                if (obj == null) return false;

                ListKey key2 = (ListKey) obj;

                if (_bytes.Length != key2._bytes.Length) return false;
                for (int i=0; i<_bytes.Length; i++) if (_bytes[i] != key2._bytes[i]) return false;
                return true;
            }

            public override int GetHashCode()
            {
                if (_bytes.Length >= 4) {
                    return _bytes[0] << 24 + _bytes[1] << 16 + _bytes[2] << 8 + _bytes[3];
                }
                return _bytes[0];
            }
        }


        protected Boolean _fSymmetricSecret = false;
        protected CBORObject[] _kid = new CBORObject[2];
        protected byte[][] _SessionId = new byte[2][];
        protected byte[][] _Nonce = new byte[2][];
        protected OneKey[] _Keys = new OneKey[2];
        protected CBORObject _algKeyAgree;
        protected CBORObject _algAEAD;
        protected CBORObject _algSign;
        protected byte[][] _Messages = new byte[3][];
        protected OneKey _SigningKey;
        protected IDigest _MessageDigest = null;
        protected byte[] _LastMessageAuthenticator;

        

        public byte[] KeyIdentifier {
            get { return _kid[1].GetByteString(); }
        }

        protected OneKey _SharedSecret;
        public OneKey SharedSecret {
            // get { return _SharedSecret; }
            set
            {
                if (!value[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_Octet)) throw new ArgumentException();
                _SharedSecret = value;
            }
        }

        protected byte[] _SecretSalt
        {
            get
            {
                if (_SharedSecret == null) return null;
                return _SharedSecret[CoseKeyParameterKeys.Octet_k].GetByteString();
            }
        }

        public OneKey SigningKey {
            get { return _SigningKey; }
            set { _SigningKey = value; }
        }

        /// <summary>
        /// Compute and derive the keys based on the input data
        /// </summary>
        /// <param name="keys">Public and Private DH keys to use for creating shared secret</param>
        /// <param name="salt">A shared symmetric key if one exists</param>
        /// <param name="otherData">SuppPubInfo other data bytes - changes for each message</param>
        /// <param name="algAEAD">Symmetric algorithm for encryption</param>
        /// <returns>array of two byte arrays.  The first is the key, the second is the IV</returns>
        protected static byte[][] _DeriveKeys(OneKey[] keys, byte[] salt, byte[] otherData, CBORObject algAEAD)
        {
            int cbitKey = 0;
            int cbitIV = 0;

            byte[] secret = ECDH_GenerateSecret(keys);

            if (algAEAD.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) algAEAD.AsInt32()) {
                case AlgorithmValuesInt.AES_CCM_64_64_128:
                    cbitKey = 128;
                    cbitIV = 58;
                    break;

                default:
                    throw new Exception("Unknown Algorithm");

                }
            }
            else if (algAEAD.Type != CBORType.TextString) {
                throw new Exception("Internal Error");
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
            obj.Add(cbitKey/8);
            obj.Add(CBORObject.FromObject(new byte[0]));
            obj.Add(otherData);
            context.Add(obj);           // SuppPubInfo

            byte[] rgbContext = context.EncodeToBytes();

            byte[][] returnValue = new byte[2][];

            returnValue[0] = HKDF(secret, salt, rgbContext, cbitKey, new Sha256Digest());

            obj[0] = CBORObject.FromObject(cbitIV/8);
            context[0] = CBORObject.FromObject("IV-GENERATION");
            returnValue[1] = HKDF(secret, salt, rgbContext, cbitIV, new Sha256Digest());
            return returnValue;
        }

        /// <summary>
        /// Select an algorithm from the two lists that we are going to use.
        /// Rules are - take the first one in list 2 that is also in list1
        /// If there are no common entries then throw an exception.
        /// </summary>
        /// <param name="algList">Their list of algorithms.</param>
        /// <param name="algList2">Our list of algorithms.</param>
        /// <returns></returns>
        protected static CBORObject _SelectAlgorithm(CBORObject algList, CBORObject[] algList2)
        {
            foreach (CBORObject alg in algList2) {
                for (int i = 0; i < algList.Count; i++) {
                    if (alg.Equals(algList[i])) return algList[i];
                }
            }

            throw new Exception("No Common Algorithm Found");
        }

        protected static byte[] Concatenate(byte[][] arrays)
        {
            byte[] rv = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;
            foreach (byte[] array in arrays) {
                System.Buffer.BlockCopy(array, 0, rv, offset, array.Length);
                offset += array.Length;
            }
            return rv;
        }

        protected static byte[] ConcatenateAndHash(byte[][] arrays, IDigest digest)
        {
            byte[] data = Concatenate(arrays);

            digest.Reset();
            digest.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);

            return result;
        }

        protected static byte[] ECDH_GenerateSecret(OneKey[] keys)
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

        public CoAP.OSCOAP.SecurityContext CreateSecurityContext()
        {
            byte[] otherData = Concatenate(new byte[][] {_Messages[0], _Messages[1], _Messages[2]});
            byte[][] MasterSecret = _DeriveKeys(_Keys, _SecretSalt, otherData, CBORObject.FromObject("EDHOC OSCOAP Master Secret"));
            byte[][] MasterSalt = _DeriveKeys(_Keys, _SecretSalt, otherData, CBORObject.FromObject("EDHOC OSCOAP Master Salt"));

            return CoAP.OSCOAP.SecurityContext.DeriveContext(MasterSecret[0], _SessionId[0], _SessionId[1], MasterSalt[0], _algAEAD,
                _algKeyAgree);
        }
    }

    public class EdhocInitiator : EdhocBase
    {
        /// <summary>
        /// Create an EDHOC context for a suplicant to generate messages from.
        /// </summary>
        /// <param name="contextKey">Either shared secret or signing to key to used to do identity proofing for</param>
        public EdhocInitiator(OneKey contextKey)
        {
            switch ((GeneralValuesInt)contextKey[CoseKeyKeys.KeyType].AsInt32()) {
                case GeneralValuesInt.KeyType_Octet:
                    _fSymmetricSecret = true;
                    _SharedSecret = contextKey;
                    break;

                case GeneralValuesInt.KeyType_EC2:
                case GeneralValuesInt.KeyType_OKP:
                    _fSymmetricSecret = false;
                    if (!contextKey.ContainsName(CoseKeyParameterKeys.EC_D)) {
                        throw new Exception("Need to supply a private key with the signing key");
                    }
                    _SigningKey = contextKey;
                    break;

                case GeneralValuesInt.KeyType_RSA:
                default:
                    throw new Exception("Unknown key type for secret");
            }

            //  Save the items in the "Our" side of the arrays.

            _kid[0] = contextKey[CoseKeyKeys.KeyIdentifier];
            _SessionId[0] = Encoding.UTF8.GetBytes("kid client");
            _Nonce[0] = Encoding.UTF8.GetBytes("Nonce Client");
            _Keys[0] = OneKey.GenerateKey(null, GeneralValues.KeyType_OKP, "X25519");
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
            msg.Add(_Keys[0].PublicKey().AsCBOR());

            CBORObject obj = CBORObject.NewArray();         // Key Agree algorithms
            obj.Add(AlgorithmValues.ECDH_SS_HKDF_256);
            msg.Add(obj);

            obj = CBORObject.NewArray();
            obj.Add(AlgorithmValues.AES_CCM_64_64_128);     // AEAD algorithms
            msg.Add(obj);

            if (_fSymmetricSecret) {
                msg.Add(_SharedSecret[CoseKeyKeys.KeyIdentifier]);
            }
            else {
                obj = CBORObject.NewArray();                // SIG verify algorithms
                obj.Add(AlgorithmValuesInt.ECDSA_256);
                // obj.Add(AlgorithmValues.EdDSA);
                msg.Add(obj);

                msg.Add(obj);                               // SIG generate algorithms
            }

            _Messages[0] = msg.EncodeToBytes();         // message_1
            _LastMessageAuthenticator = _Messages[0];
            return _Messages[0];
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="msgData"></param>
        /// <param name="keySetPublic"></param>
        public void ParseMessage2(byte[] msgData, KeySet keySetPublic)
        {
            int msgIndex;
            CBORObject algVerify = null;

            CBORObject msg = CBORObject.DecodeFromBytes(msgData);
            if (msg.Type != CBORType.Array) throw new Exception("Invalid message");

            _Messages[1] = msgData;

            if (_fSymmetricSecret) {
                if (msg[0].AsInt16() != 5) throw new Exception("Invalid Message");
            }
            else {
                if (msg[0].AsInt16() != 2) throw new Exception("Invalid Message");
            }

            _SessionId[1] = msg[2].GetByteString();       // S_V
            _Nonce[1] = msg[3].GetByteString();           // N_V
            _Keys[1] = new OneKey(msg[4]);                // E_V
            _algKeyAgree = msg[5];                        // HKDF_V
            _algAEAD = msg[6];                            // AAEAD_V
            if (_fSymmetricSecret) {
                msgIndex = 7;
            }
            else {
                algVerify = msg[7];                             // SIG_V
                _algSign = _SelectAlgorithm(msg[8], new CBORObject[] { AlgorithmValues.ECDSA_256 });                        // SIG_U
                msgIndex = 9;
            }

            //  What is the hash algorithm to use?
            switch ((AlgorithmValuesInt) _algKeyAgree.AsInt32()) {
            case AlgorithmValuesInt.ECDH_SS_HKDF_256:
                _MessageDigest = new Sha256Digest();
                break;

            case AlgorithmValuesInt.ECDH_SS_HKDF_512:
                _MessageDigest = new Sha512Digest();
                break;

            }


            Encrypt0Message enc0 = (Encrypt0Message)Com.AugustCellars.COSE.Message.DecodeFromBytes(msg[msgIndex].EncodeToBytes(), Tags.Encrypt0);

            msg.Remove(msg[msgIndex]);
            byte[] data_2 = msg.EncodeToBytes();
            byte[] aad_2 = ConcatenateAndHash(new byte[2][] { _Messages[0], data_2 }, _MessageDigest);
 
            byte[][] useKeys = _DeriveKeys(_Keys, _SecretSalt, aad_2, _algAEAD);
            byte[] encKey = useKeys[0];
            enc0.AddAttribute(HeaderKeys.Algorithm, _algAEAD, Attributes.DO_NOT_SEND);
            enc0.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(useKeys[1]), Attributes.DO_NOT_SEND);
            enc0.SetExternalData(aad_2);
            byte[] body = enc0.Decrypt(encKey);

            if (!_fSymmetricSecret) {
                CBORObject encBody = CBORObject.DecodeFromBytes(body);

                Sign1Message sign1 = (Sign1Message)Com.AugustCellars.COSE.Message.DecodeFromBytes(encBody[0].GetByteString(), Tags.Sign1);
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

            _LastMessageAuthenticator = ConcatenateAndHash(new byte[2][] {_LastMessageAuthenticator, msgData}, _MessageDigest);
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

            byte[] aad_3 = ConcatenateAndHash(new byte[2][] { _LastMessageAuthenticator, msg.EncodeToBytes() }, _MessageDigest);

            byte[] signBody = new byte[0];
            if (!_fSymmetricSecret) {
                Sign1Message sign1 = new Sign1Message(false, false);
                sign1.SetContent(aad_3);
                sign1.AddAttribute(HeaderKeys.Algorithm, _algSign, Attributes.DO_NOT_SEND);
                sign1.AddAttribute(HeaderKeys.KeyId, _SigningKey[CoseKeyKeys.KeyIdentifier], Attributes.UNPROTECTED);
                sign1.Sign(_SigningKey);

                CBORObject obj = CBORObject.NewArray();
                obj.Add(sign1.EncodeToBytes());

                signBody = obj.EncodeToBytes();
            }

            byte[][] encKeys = _DeriveKeys(_Keys, _SecretSalt, aad_3, _algAEAD);

            Encrypt0Message enc = new Encrypt0Message(false);
            enc.SetContent(signBody);
            enc.SetExternalData(aad_3);
            enc.AddAttribute(HeaderKeys.Algorithm, _algAEAD, Attributes.DO_NOT_SEND);
            enc.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(encKeys[1]), Attributes.DO_NOT_SEND);
            enc.Encrypt(encKeys[0]);

            msg.Add(enc.EncodeToBytes());

            byte[] msgOut = msg.EncodeToBytes();

            _LastMessageAuthenticator = ConcatenateAndHash(new byte[2][] {_LastMessageAuthenticator, msgOut}, _MessageDigest);

            return msgOut;
        }
    }

    public class EdhocResponder : EdhocBase
    {
        protected static Dictionary<ListKey, EdhocResponder> MessageList = new Dictionary<ListKey, EdhocResponder>();

        /// <summary>
        /// Given a first message in the Edhoc protocol, parse the message into pieces
        /// and fill in the data struture elements to continue processing.
        /// Throw an exception on failures.
        /// </summary>
        /// <param name="msgData"></param>
        /// <returns></returns>
        public static EdhocResponder ParseMessage1(byte[] msgData)
        {
            EdhocResponder edhoc = new EdhocResponder();
            CBORObject msg = CBORObject.DecodeFromBytes(msgData);
            if (msg.Type != CBORType.Array) throw new Exception("Invalid message");
            if (msg[0].AsInt32() == 1) {
                edhoc._fSymmetricSecret = false;
            }
            else if (msg[0].AsInt32() == 4) {
                edhoc._fSymmetricSecret = true;
            }
            else throw new Exception("Invalid Message");

            // Fill in "their" data into the different arrays

            edhoc._Messages[0] = msgData;               // message_1

            edhoc._SessionId[1] = msg[1].GetByteString();
            edhoc._Nonce[1] = msg[2].GetByteString();
            edhoc._Keys[1] = new OneKey(msg[3]);        // Their one time key
            edhoc._algKeyAgree = _SelectAlgorithm(msg[4], new CBORObject[]{AlgorithmValues.ECDH_SS_HKDF_256});
            edhoc._algAEAD = _SelectAlgorithm(msg[5], new CBORObject[] { AlgorithmValues.AES_CCM_64_64_128});
            if (!edhoc._fSymmetricSecret) {
                edhoc._algSign = _SelectAlgorithm(msg[6], new CBORObject[] { AlgorithmValues.ECDSA_256});
            }

            edhoc._Keys[0] = OneKey.GenerateKey(null, edhoc._Keys[1][CoseKeyKeys.KeyType], "X25519" /*edhoc._Keys[1][CoseKeyParameterKeys.EC_Curve].AsString()*/);
            edhoc._SessionId[0] = Encoding.UTF8.GetBytes("Kid Svr");
            edhoc._Nonce[0] = Encoding.UTF8.GetBytes("Server Nonce");

            MessageList.Add(new ListKey(edhoc._SessionId[0]), edhoc);

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
            msg.Add(_Keys[0].PublicKey().AsCBOR()); // E_V
            msg.Add(_algKeyAgree);      // HKDF_V
            msg.Add(_algAEAD);          // AEAD_V
            if (!_fSymmetricSecret) {
                msg.Add(_algSign);          // SIG_V

                obj = CBORObject.NewArray();
                obj.Add(AlgorithmValuesInt.ECDSA_256);
                obj.Add(AlgorithmValues.EdDSA);
                msg.Add(obj);               // SIGs_V
            }

            byte[] data2 = msg.EncodeToBytes();
            byte[] aad_2 = Concatenate(new byte[2][] { _Messages[0], data2 });   // M00TODO - hash message[0] before passing it in.

            byte[][] useKeys = _DeriveKeys(_Keys, _SecretSalt, aad_2, _algAEAD);
            byte[] aeadKey = useKeys[0];

            byte[] signResult = new byte[0];
            if (!_fSymmetricSecret) {
                Sign1Message sign1 = new Sign1Message(false, false);
                sign1.SetContent(aad_2);
                sign1.AddAttribute(HeaderKeys.KeyId, _SigningKey[CoseKeyKeys.KeyIdentifier], Attributes.UNPROTECTED);

                sign1.Sign(_SigningKey);
                signResult = sign1.EncodeToBytes();
            }

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

        static public EdhocResponder ParseMessage3(byte[] msgData, KeySet serverKeys)
        {
            int msgIndex;
            CBORObject algVerify = null;

            CBORObject msg = CBORObject.DecodeFromBytes(msgData);
            if (msg.Type != CBORType.Array) throw new Exception("Invalid message");

            EdhocResponder edhoc = MessageList[new ListKey(msg[1].GetByteString())];

            edhoc._Messages[2] = msgData;

            if (edhoc._fSymmetricSecret) {
                if (msg[0].AsInt16() != 6) throw new Exception("Invalid Message");
            }
            else {
                if (msg[0].AsInt16() != 3) throw new Exception("Invalid Message");
            }


            Encrypt0Message enc0 = (Encrypt0Message)Com.AugustCellars.COSE.Message.DecodeFromBytes(msg[2].GetByteString(), Tags.Encrypt0);

            msg.Remove(msg[2]);

            byte[] data_3 = msg.EncodeToBytes();
            byte[] aad_3 = Concatenate(new byte[][] { edhoc._Messages[0], edhoc._Messages[1], data_3 });

            byte[][] useKeys = _DeriveKeys(edhoc._Keys, edhoc._SecretSalt, aad_3, edhoc._algAEAD);
            byte[] encKey = useKeys[0];

            enc0.AddAttribute(HeaderKeys.Algorithm, edhoc._algAEAD, Attributes.DO_NOT_SEND);
            enc0.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(useKeys[1]), Attributes.DO_NOT_SEND);
            enc0.SetExternalData(aad_3);
            byte[] body = enc0.Decrypt(encKey);

            if (!edhoc._fSymmetricSecret) {
                CBORObject encBody = CBORObject.DecodeFromBytes(body);

                Sign1Message sign1 = (Sign1Message)Com.AugustCellars.COSE.Message.DecodeFromBytes(encBody[0].GetByteString(), Tags.Sign1);
                sign1.AddAttribute(HeaderKeys.Algorithm, edhoc._algSign, Attributes.DO_NOT_SEND);

                CBORObject kidObject = sign1.FindAttribute(HeaderKeys.KeyId);
                byte[] kid = null;
                if (kidObject != null) kid = kidObject.GetByteString();
                sign1.SetExternalData(aad_3);

                KeySet keys = new KeySet();
                foreach (OneKey sigKey in serverKeys) {
                    if (sigKey.HasKid(kid)) keys.AddKey(sigKey);
                }

                List<OneKey> ks = new List<OneKey>();
                List<OneKey> ks2 = ks.Where(f => f.HasKid(kid)).ToList();

                OneKey signingKey = null;
                foreach (OneKey sigKey in keys) {
                    try {
                        sign1.Validate(sigKey);
                        signingKey = sigKey;
                    }
                    catch (Exception) {
                        // nop;
                    }
                }

                if (signingKey == null) throw new Exception("Unable to complete - no signing key found");
            }
            else {
                // body is the EXT_3 value
            }

            return edhoc;
        }
    }
}
