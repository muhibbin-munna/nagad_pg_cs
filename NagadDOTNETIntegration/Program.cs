using NagadDOTNETIntegration.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

namespace NagadDOTNETIntegration
{
    class Program
    {
        public static string marchentPrivateKey = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCJakyLqojWTDAVUdNJLvuXhROV+LXymqnukBrmiWwTYnJYm9r5cKHj1hYQRhU5eiy6NmFVJqJtwpxyyDSCWSoSmIQMoO2KjYyB5cDajRF45v1GmSeyiIn0hl55qM8ohJGjXQVPfXiqEB5c5REJ8Toy83gzGE3ApmLipoegnwMkewsTNDbe5xZdxN1qfKiRiCL720FtQfIwPDp9ZqbG2OQbdyZUB8I08irKJ0x/psM4SjXasglHBK5G1DX7BmwcB/PRbC0cHYy3pXDmLI8pZl1NehLzbav0Y4fP4MdnpQnfzZJdpaGVE0oI15lq+KZ0tbllNcS+/4MSwW+afvOw9bazAgMBAAECggEAIkenUsw3GKam9BqWh9I1p0Xmbeo+kYftznqai1pK4McVWW9//+wOJsU4edTR5KXK1KVOQKzDpnf/CU9SchYGPd9YScI3n/HR1HHZW2wHqM6O7na0hYA0UhDXLqhjDWuM3WEOOxdE67/bozbtujo4V4+PM8fjVaTsVDhQ60vfv9CnJJ7dLnhqcoovidOwZTHwG+pQtAwbX0ICgKSrc0elv8ZtfwlEvgIrtSiLAO1/CAf+uReUXyBCZhS4Xl7LroKZGiZ80/JE5mc67V/yImVKHBe0aZwgDHgtHh63/50/cAyuUfKyreAH0VLEwy54UCGramPQqYlIReMEbi6U4GC5AQKBgQDfDnHCH1rBvBWfkxPivl/yNKmENBkVikGWBwHNA3wVQ+xZ1Oqmjw3zuHY0xOH0GtK8l3Jy5dRL4DYlwB1qgd/Cxh0mmOv7/C3SviRk7W6FKqdpJLyaE/bqI9AmRCZBpX2PMje6Mm8QHp6+1QpPnN/SenOvoQg/WWYM1DNXUJsfMwKBgQCdtddE7A5IBvgZX2o9vTLZY/3KVuHgJm9dQNbfvtXw+IQfwssPqjrvoU6hPBWHbCZl6FCl2tRh/QfYR/N7H2PvRFfbbeWHw9+xwFP1pdgMug4cTAt4rkRJRLjEnZCNvSMVHrri+fAgpv296nOhwmY/qw5Smi9rMkRY6BoNCiEKgQKBgAaRnFQFLF0MNu7OHAXPaW/ukRdtmVeDDM9oQWtSMPNHXsx+crKY/+YvhnujWKwhphcbtqkfj5L0dWPDNpqOXJKV1wHt+vUexhKwus2mGF0flnKIPG2lLN5UU6rs0tuYDgyLhAyds5ub6zzfdUBG9Gh0ZrfDXETRUyoJjcGChC71AoGAfmSciL0SWQFU1qjUcXRvCzCK1h25WrYS7E6pppm/xia1ZOrtaLmKEEBbzvZjXqv7PhLoh3OQYJO0NM69QMCQi9JfAxnZKWx+m2tDHozyUIjQBDehve8UBRBRcCnDDwU015lQN9YNb23Fz+3VDB/LaF1D1kmBlUys3//r2OV0Q4ECgYBnpo6ZFmrHvV9IMIGjP7XIlVa1uiMCt41FVyINB9SJnamGGauW/pyENvEVh+ueuthSg37e/l0Xu0nm/XGqyKCqkAfBbL2Uj/j5FyDFrpF27PkANDo99CdqL5A4NQzZ69QRlCQ4wnNCq6GsYy2WEJyU2D+K8EBSQcwLsrI7QL7fvQ=="; //Get just the base64 content.
        public static string marchentPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiWpMi6qI1kwwFVHTSS77l4UTlfi18pqp7pAa5olsE2JyWJva+XCh49YWEEYVOXosujZhVSaibcKccsg0glkqEpiEDKDtio2MgeXA2o0ReOb9RpknsoiJ9IZeeajPKISRo10FT314qhAeXOURCfE6MvN4MxhNwKZi4qaHoJ8DJHsLEzQ23ucWXcTdanyokYgi+9tBbUHyMDw6fWamxtjkG3cmVAfCNPIqyidMf6bDOEo12rIJRwSuRtQ1+wZsHAfz0WwtHB2Mt6Vw5iyPKWZdTXoS822r9GOHz+DHZ6UJ382SXaWhlRNKCNeZavimdLW5ZTXEvv+DEsFvmn7zsPW2swIDAQAB";
        public static string nagadPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjBH1pFNSSRKPuMcNxmU5jZ1x8K9LPFM4XSu11m7uCfLUSE4SEjL30w3ockFvwAcuJffCUwtSpbjr34cSTD7EFG1Jqk9Gg0fQCKvPaU54jjMJoP2toR9fGmQV7y9fz31UVxSk97AqWZZLJBT2lmv76AgpVV0k0xtb/0VIv8pd/j6TIz9SFfsTQOugHkhyRzzhvZisiKzOAAWNX8RMpG+iqQi4p9W9VrmmiCfFDmLFnMrwhncnMsvlXB8QSJCq2irrx3HG0SJJCbS5+atz+E1iqO8QaPJ05snxv82Mf4NlZ4gZK0Pq/VvJ20lSkR+0nk+s/v3BgIyle78wjZP1vWLU4wIDAQAB";
        static async System.Threading.Tasks.Task Main(string[] args)
        {
            Console.WriteLine("Nagad eCommerce Integration!\n");

            Console.WriteLine("Merchant ID:" + GlobalVariables.MerchantId);
            Console.WriteLine("Request Date Time:" + GlobalVariables.RequestDateTime);// Format should be 20200827134915
            Console.WriteLine("Random Number:" + GlobalVariables.RandomNumber + "\n");// Should be integer number and maximum length is 20
            
            string OrderId = "Order" + GlobalVariables.RequestDateTime; // Customer Order Number: Should be unique

            #region Initialize API Data Preparation

            // Create JSON Object
            var initializeJSON = new
            {
                merchantId = GlobalVariables.MerchantId,
                orderId = OrderId,
                datetime = GlobalVariables.RequestDateTime,
                challenge = GlobalVariables.RandomNumber
            };
            // Serialize JSON data to pass through Initialize API
            string initializeJsonData = JsonConvert.SerializeObject(initializeJSON);

            // Encrypt the JSON Data
            string sensitiveData = EncryptWithPublic(initializeJsonData);

            // Generate Signature on JSON Data
            string signatureValue = SignWithMarchentPrivateKey(initializeJsonData);


            // Prepare Final JSON for Initialize API
            var jSON = new
            {
                datetime = GlobalVariables.RequestDateTime,
                sensitiveData = sensitiveData,
                signature = signatureValue
            };
            // Serialize JSON data to pass through Initialize API
            string jSonData = JsonConvert.SerializeObject(jSON);

            #endregion

            #region Call Initialize API

            var responseContent = "";
            try
            {
                var httpContent = new StringContent(jSonData, Encoding.UTF8, "application/json");

                using (var httpClient = new HttpClient())
                {
                    httpClient.DefaultRequestHeaders.Add("X-KM-IP-V4", "192.168.0.1");
                    httpClient.DefaultRequestHeaders.Add("X-KM-MC-Id", GlobalVariables.MerchantId);
                    httpClient.DefaultRequestHeaders.Add("X-KM-Client-Type", "PC_WEB");
                    httpClient.DefaultRequestHeaders.Add("X-KM-Api-Version", "v-0.2.0");
                    // Do the actual request and await the response
                    var httpResponse = await httpClient.PostAsync(GlobalVariables.InitializeAPI + GlobalVariables.MerchantId + "/" + OrderId, httpContent);

                    // If the response contains content we want to read it!
                    if (httpResponse.Content != null)
                    {
                        responseContent = await httpResponse.Content.ReadAsStringAsync();
                    }
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
            Console.WriteLine("Initialize API Response:" + responseContent + "\n");
            #endregion

            #region Process Initialize API Returned Values & Verify Signature

            dynamic response = JObject.Parse(responseContent);
            string returnedSensitiveData = response.sensitiveData;

            string returnedSignature = response.signature;

            //Decrypt Sensitive Data
            string decryptedSensitiveData = Decrypt(returnedSensitiveData);

            // Initialize API Signature Verification
            var v = Verify(decryptedSensitiveData, returnedSignature, nagadPublicKey, Encoding.UTF8, HashAlgorithmName.SHA256);
            if (!v)
            {
                Console.WriteLine("Signature Verification Failed");
                return;
            }

            //Process Decrypted Data
            dynamic responsevalue = JObject.Parse(decryptedSensitiveData);
            string challenge = responsevalue.challenge;
            string paymentRefId = responsevalue.paymentReferenceId;
            string amount = "100";

            // Create JSON Object
            var paymentJSON = new
            {
                merchantId = GlobalVariables.MerchantId,
                orderId = OrderId,
                currencyCode = "050",
                amount = amount,
                challenge = challenge
            };
 
            string paymentJsonData = JsonConvert.SerializeObject(paymentJSON);


            string paymentSensitiveData = EncryptWithPublic(paymentJsonData);

            // Generate Signature on JSON Data
            string paymentSignatureValue = SignWithMarchentPrivateKey(paymentJsonData);

            
            string merchantCallbackURL = "http://sandbox.mynagad.com:10707/merchant-server/web/confirm"; //merchant Callback URL - as you want
            
            // Prepare Final JSON for Payment API
            var paymentFinalJSON = new
            {
                sensitiveData = paymentSensitiveData,
                signature = paymentSignatureValue,
                merchantCallbackURL = merchantCallbackURL
            };

            // Serialize JSON data to pass through Initialize API
            string finalJSONData = JsonConvert.SerializeObject(paymentFinalJSON);

            #endregion

            #region Call Checkout API
            var br_ResponseContent = "";
            try
            {
                var br_httpContent = new StringContent(finalJSONData, Encoding.UTF8, "application/json");

                using (var br_httpClient = new HttpClient())
                {
                    br_httpClient.DefaultRequestHeaders.Add("X-KM-IP-V4", "192.168.0.1");
                    br_httpClient.DefaultRequestHeaders.Add("X-KM-MC-Id", GlobalVariables.MerchantId);
                    br_httpClient.DefaultRequestHeaders.Add("X-KM-Client-Type", "PC_WEB");
                    br_httpClient.DefaultRequestHeaders.Add("X-KM-Api-Version", "v-0.2.0");
                    // Do the actual request and await the response
                    var httpResponse = await br_httpClient.PostAsync(GlobalVariables.CheckOutAPI + paymentRefId, br_httpContent);

                    // If the response contains content we want to read it!
                    if (httpResponse.Content != null)
                    {
                        br_ResponseContent = await httpResponse.Content.ReadAsStringAsync();
                    }
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
            Console.WriteLine("Checkout API Response:" + br_ResponseContent + "\n");

            #endregion

            #region Process Checkout API Response
            dynamic co_Response = JObject.Parse(br_ResponseContent);
            

            if (co_Response.status == "Success")
                Console.WriteLine("Customer is redirecting to following Site:" + co_Response.callBackUrl + "\n");
            else
                Console.WriteLine("Failed");
        }
        #endregion


        #region Helper Functions

        #region EncryptWithPublicKey
        public static string EncryptWithPublic(string baseText)
        {
            try
            {
                //  System.Diagnostics.Debug.WriteLine("merchantId: " + jsonPlainData.merchantId + "-" + "orderId: " + jsonPlainData.orderId + "-" + "dateTime: " + jsonPlainData.dateTime + "-" + "challenge: " + jsonPlainData.challenge);
                var rng = new Random();
                RSA cipher = myfun(0);
                var plaintext = baseText;
                byte[] data = Encoding.UTF8.GetBytes(plaintext);

                byte[] cipherText = cipher.Encrypt(data, RSAEncryptionPadding.Pkcs1);
                var encryptedData = Convert.ToBase64String(cipherText);
                return encryptedData;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        #endregion

        #region SignWithMarchentPrivateKey
        public static string SignWithMarchentPrivateKey(string baseText)
        {
            try
            {
                var rsa = myfun(1);
                byte[] dataBytes = Encoding.UTF8.GetBytes(baseText);
                var signatureBytes = rsa.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return Convert.ToBase64String(signatureBytes);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        #endregion

        #region Decrypt
        public static string Decrypt(string plainText)
        {
            var rsa = myfun(1);
            if (rsa == null)
            {
                throw new Exception("_privateKeyRsaProvider is null");
            }
            string decryptedData = Encoding.UTF8.GetString(rsa.Decrypt(Convert.FromBase64String(plainText), RSAEncryptionPadding.Pkcs1));
            return decryptedData;
        }
        #endregion

        #region RSA Encryption
        private static RSA myfun(int num)
        {
            try
            {
                if (num == 1)
                {
                    var privateKeyBytes = Convert.FromBase64String(marchentPrivateKey);
                    int myarray;
                    var rsa = RSA.Create();

                    rsa.ImportPkcs8PrivateKey(privateKeyBytes, out myarray);
                    return rsa;
                }
                if (num == 0)
                {
                    var publicKeyBytes = Convert.FromBase64String(nagadPublicKey);
                    int myarray;
                    var rsa = RSA.Create();

                    rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out myarray);
                    return rsa;
                }
            }
            catch (CryptographicException e)
            {

                Console.WriteLine(e.Message);
            }

            return null;
        }
        #endregion

        #region Signature Verify
        public static bool Verify(string data, string sign, string publicKey, Encoding encoding, HashAlgorithmName hashAlgorithmName)
        {
            byte[] dataBytes = encoding.GetBytes(data);
            byte[] signBytes = Convert.FromBase64String(sign);
            RSA rsa = CreateRsaProviderFromPublicKey(publicKey);
            var verify = rsa.VerifyData(dataBytes, signBytes, hashAlgorithmName, RSASignaturePadding.Pkcs1);
            return verify;
        }

        private static RSA CreateRsaProviderFromPublicKey(string publicKeyString)
        {
            // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
            byte[] seqOid = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            byte[] seq = new byte[15];

            var x509Key = Convert.FromBase64String(publicKeyString);

            // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
            using (MemoryStream mem = new MemoryStream(x509Key))
            {
                using (BinaryReader binr = new BinaryReader(mem))  //wrap Memory Stream with BinaryReader for easy reading
                {
                    byte bt = 0;
                    ushort twobytes = 0;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8230)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    seq = binr.ReadBytes(15);       //read the Sequence OID
                    if (!CompareBytearrays(seq, seqOid))    //make sure Sequence for OID is correct
                        return null;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8103) //data read as little endian order (actual data order for Bit String is 03 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8203)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    bt = binr.ReadByte();
                    if (bt != 0x00)     //expect null byte next
                        return null;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8230)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    twobytes = binr.ReadUInt16();
                    byte lowbyte = 0x00;
                    byte highbyte = 0x00;

                    if (twobytes == 0x8102) //data read as little endian order (actual data order for Integer is 02 81)
                        lowbyte = binr.ReadByte();  // read next bytes which is bytes in modulus
                    else if (twobytes == 0x8202)
                    {
                        highbyte = binr.ReadByte(); //advance 2 bytes
                        lowbyte = binr.ReadByte();
                    }
                    else
                        return null;
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };   //reverse byte order since asn.1 key uses big endian order
                    int modsize = BitConverter.ToInt32(modint, 0);

                    int firstbyte = binr.PeekChar();
                    if (firstbyte == 0x00)
                    {   //if first byte (highest order) of modulus is zero, don't include it
                        binr.ReadByte();    //skip this null byte
                        modsize -= 1;   //reduce modulus buffer size by 1
                    }

                    byte[] modulus = binr.ReadBytes(modsize);   //read the modulus bytes

                    if (binr.ReadByte() != 0x02)            //expect an Integer for the exponent data
                        return null;
                    int expbytes = (int)binr.ReadByte();        // should only need one byte for actual exponent data (for all useful values)
                    byte[] exponent = binr.ReadBytes(expbytes);

                    // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                    var rsa = System.Security.Cryptography.RSA.Create();
                    RSAParameters rsaKeyInfo = new RSAParameters
                    {
                        Modulus = modulus,
                        Exponent = exponent
                    };
                    rsa.ImportParameters(rsaKeyInfo);

                    return rsa;
                }

            }
        }

        private static bool CompareBytearrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;
            int i = 0;
            foreach (byte c in a)
            {
                if (c != b[i])
                    return false;
                i++;
            }
            return true;
        }

        #endregion

     #endregion
    }
}
