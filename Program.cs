using log4net;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CrypWalk
{
    class Program
    {
        private static readonly ILog log = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        static void Main(string[] args)
        {
            ///////////// FIRST EXAMPLE ///////////////
            log.Info("<<< FIRST EXAMPLE >>>"); log.Info("");
            var plainPwd = "fimiprod"; log.Info("Password >>> " + plainPwd);
            var nextChallenge = "06253765"; log.Info("Next Challenge >>> " + nextChallenge);
            
            //Step 1 - 
            string capsPwd = plainPwd.ToUpper();
            string subStrCapsPwd_8 = SubStrAndPad(capsPwd, 8);
            string subStrCapsPwd_16 = SubStrAndPad(capsPwd, 16);

            log.Info("Caps_Password >>> " + capsPwd);
            log.Info("PadTrail_8 >>> " + subStrCapsPwd_8);
            log.Info("PadTrail_16 >>> " + subStrCapsPwd_16);
            

            // Step 2 - 
            string tripleDES = TripleDesEncrypt(subStrCapsPwd_8, subStrCapsPwd_16);
            log.Info("3DES PadTrail >>> " + tripleDES);
            string pwdHash = HexEncode(tripleDES);
            log.Info("pwdHash >>> " + pwdHash);


            // Step 3 - 
            var h2S = HexDecode(pwdHash);
            string nxtChgEnc = DES_Encode(nextChallenge, subStrCapsPwd_16);
            log.Info("Next Challenge Encryption >>> " + nxtChgEnc);
            
            log.Info("");  log.Info("<<< END >>>"); log.Info("");
            /////////////////////////////////////////////////
            




            ///////////// SECOND EXAMPLE ///////////////
            log.Info(""); log.Info("<<< SECOND EXAMPLE >>>"); log.Info("");
            var plainPwd_2 = "abpi0001"; log.Info("Password >>> " + plainPwd_2);

            //Step 1 - 
            string capsPwd_2 = plainPwd_2.ToUpper();
            string subStrCapsPwd_8_2 = SubStrAndPad(capsPwd_2, 8);
            string subStrCapsPwd_16_2 = SubStrAndPad(capsPwd_2, 16);

            log.Info("Caps_Password >>> " + capsPwd_2);
            log.Info("PadTrail_8 >>> " + subStrCapsPwd_8_2);
            log.Info("PadTrail_16 >>> " + subStrCapsPwd_16_2);


            string hex_pwd_2 = HexEncode(capsPwd_2);
            log.Info("Hex_Password >>> " + hex_pwd_2);


            // Step 2 - 
            string des_2 = DES_Encode(hex_pwd_2, hex_pwd_2);
            log.Info("First_DES >>> " + des_2);
            string pwdHash_2 = HexEncode(des_2);

            // Did not continue with the others since the first DES is wrong.

            log.Info(""); log.Info("<<< END >>>"); log.Info("");
            /////////////////////////////////////////////////







            Console.ReadLine();
        }


        public static string SubStrAndPad(string strVar, int strLength)
        {
            string paddedStr = string.Empty;
            string subStr = string.Empty;

            if (strLength >= strVar.Length)
            {
                if (strVar.Length >= strLength)
                {
                    subStr = strVar.Substring(0, strLength);
                }
                else
                {
                    subStr = strVar;
                }
                paddedStr = subStr.PadRight(strLength, ' ');
            }
            else
            {
                log.Debug("SubStrAndPad >>> strLength value is invalid");
            }

            return paddedStr;
        }


        public static string HexEncode(string plainText)
        {
            byte[] plainTextBytes = Encoding.Default.GetBytes(plainText);
            string hexString = BitConverter.ToString(plainTextBytes);
            hexString = hexString.Replace("-", "");

            return hexString;
        }


        public static string DES_Encode(string str, string key)
        {
            string encrypted_Str = string.Empty;

            try
            {
                DES DESalg = DES.Create();

                string sData = str;
                byte[] keyByte_1 = UTF8Encoding.UTF8.GetBytes(key);
                byte[] keyByte_2 = ASCIIEncoding.ASCII.GetBytes(key);
                byte[] keyByte_3 = StringToByteArray(key, 8);
                byte[] keyByte_4 = UTF8Encoding.UTF8.GetBytes(key);
                Array.Resize(ref keyByte_4, 8);
                
                // Encrypt the string to an in-memory buffer.
                byte[] Data = EncryptTextToMemory(sData, keyByte_4, keyByte_4);
                //byte[] Data = EncryptTextToMemory(sData, DESalg.Key, DESalg.IV);


                encrypted_Str = Convert.ToBase64String(Data);
                //encrypted_Str = ASCIIEncoding.ASCII.GetString(Data);

                //// Decrypt the buffer back to a string.
                //string Final = DecryptTextFromMemory(Data, DESalg.Key, DESalg.IV);

                //// Display the decrypted string to the console.
                //Console.WriteLine(Final);
            }
            catch (Exception e)
            {
                log.Error("DES_Encode >>> " + e.Message);
            }


            return encrypted_Str;
        }


        static byte[] StringToByteArray(string str, int length)
        {
            return Encoding.ASCII.GetBytes(str.PadRight(length, ' '));
        }

        public static byte[] EncryptTextToMemory(string Data, byte[] Key, byte[] IV)
        {
            try
            {
                // Create a MemoryStream.
                MemoryStream mStream = new MemoryStream();

                // Create a new DES object.
                DES DESalg = DES.Create();

                // Create a CryptoStream using the MemoryStream
                // and the passed key and initialization vector (IV).
                CryptoStream cStream = new CryptoStream(mStream,
                    DESalg.CreateEncryptor(Key, IV),
                    CryptoStreamMode.Write);

                // Convert the passed string to a byte array.
                byte[] toEncrypt = new ASCIIEncoding().GetBytes(Data);

                // Write the byte array to the crypto stream and flush it.
                cStream.Write(toEncrypt, 0, toEncrypt.Length);
                cStream.FlushFinalBlock();

                // Get an array of bytes from the
                // MemoryStream that holds the
                // encrypted data.
                byte[] ret = mStream.ToArray();

                // Close the streams.
                cStream.Close();
                mStream.Close();

                // Return the encrypted buffer.
                return ret;
            }
            catch (CryptographicException e)
            {
                log.Error("A Cryptographic error occurred: {0}", e);
                return null;
            }
        }





        public static string TripleDesEncrypt(string plainText, string Key)
        {
            var des = CreateDes(Key);
            var ct = des.CreateEncryptor();
            var input = Encoding.UTF8.GetBytes(plainText);
            var output = ct.TransformFinalBlock(input, 0, input.Length);
            return Convert.ToBase64String(output);
        }

        public static string TripleDesDecrypt(string cypherText, string Key)
        {
            var des = CreateDes(Key);
            var ct = des.CreateDecryptor();
            var input = Convert.FromBase64String(cypherText);
            var output = ct.TransformFinalBlock(input, 0, input.Length);
            return Encoding.UTF8.GetString(output);
        }

        public static TripleDES CreateDes(string key)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            TripleDES des = new TripleDESCryptoServiceProvider();
            var desKey = md5.ComputeHash(Encoding.UTF8.GetBytes(key));
            des.Key = desKey;
            des.IV = new byte[des.BlockSize / 8];
            des.Padding = PaddingMode.PKCS7;
            des.Mode = CipherMode.ECB;
            return des;
        }


        public static string encryptionMethod(string Text, string key)
        {
            string encryptedText = string.Empty;
            try
            {
                MD5CryptoServiceProvider md5Hash = new MD5CryptoServiceProvider();
                byte[] md5Bytes = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(key));
                md5Hash.Clear();
                byte[] clearBytes = Encoding.UTF8.GetBytes(Text);
                TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider();
                des.KeySize = 128;
                des.Mode = CipherMode.CBC;
                des.Padding = PaddingMode.None;
                //Array.Resize(ref md5Bytes, 8);
                des.Key = md5Bytes;   //Passing key in byte array
                //des.BlockSize = 64;
                byte[] ivBytes = new byte[8] { 0, 0, 0, 0, 0, 0, 0, 0 };
                des.IV = ivBytes;
                ICryptoTransform ct = des.CreateEncryptor();   //Interface with some result
                byte[] resultArray = ct.TransformFinalBlock(clearBytes, 0, clearBytes.Length);
                encryptedText = ByteArrayToHexString(resultArray);
            }
            catch (Exception exception)
            {
                log.Error("encryptionMethod >>> " + exception.Message);
                return "";
            }
            return encryptedText;

        }


        public static string ByteArrayToHexString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }


        public static string HexDecode(string hex)
        {

            hex = hex.Replace("-", "");
            byte[] raw = new byte[hex.Length / 2];
            for (int i = 0; i < raw.Length; i++)
            {
                raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }

            string strFromHex = Encoding.ASCII.GetString(raw);

            return strFromHex;
        }

    }
}
