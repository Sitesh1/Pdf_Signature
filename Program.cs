using iTextSharp.text.pdf.security;
using iTextSharp.text.pdf;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using iTextSharp.text;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Pkcs;
using System.Security.Cryptography;

namespace SignPdf
{
    internal class Program
    {
        static void Main(string[] args)
        {
            //PdfSignature();
            //VerifySignature();
            SignMultiple();
        }
        public static void PdfSignature()
        {
            //Type1:--
            //try
            //{
            //    string inputFilePath = @"D:\sitesh.pdf";
            //    string outputFilePath = @"D:\sinedpdf.pdf";

            //    PdfReader reader = new PdfReader(inputFilePath);
            //    using (FileStream outputStream = new FileStream(outputFilePath, FileMode.Create))
            //    {
            //        using (PdfStamper stamper = PdfStamper.CreateSignature(reader, outputStream, '\0'))
            //        {
            //            X509Certificate2 certificate = new X509Certificate2(@"D:\pfx\pfxfile.pfx", "123");

            //            PdfSignatureAppearance appearance = stamper.SignatureAppearance;
            //            appearance.SetVisibleSignature(new iTextSharp.text.Rectangle(36, 748, 144, 780), 1, "signature-field");
            //            appearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION;
            //            appearance.SignatureCreator = "Sitesh";
            //            appearance.Reason = "Reason for signing";
            //            IExternalSignature signature = new X509Certificate2Signature(certificate, "SHA-1");
            //            MakeSignature.SignDetached(appearance, signature, new X509Certificate[] { certificate }, null, null, null, 0, CryptoStandard.CMS);
            //            stamper.Close();
            //            reader.Close();
            //            Console.WriteLine("Pdf sined successfully.");
            //            Console.ReadLine();

            //        }
            //    }
            //}
            //catch (Exception ex)
            //{
            //    Console.WriteLine(ex.Message);
            //}

            string resp = "";
            byte[] by = null;
            string inputFilePath = @"D:\simplepdf.pdf";
            string outputFilePath = @"D:\sinedpdf1.pdf";
            string PfxFilePath = @"D:\pfx\pfxfile.pfx";
            PdfReader reader = new PdfReader(inputFilePath);
            //byte[] data = Encoding.UTF8.GetBytes(PfxFilePath);

            X509Certificate2 x509 = new X509Certificate2(PfxFilePath, "123");
            Org.BouncyCastle.X509.X509CertificateParser cp = new Org.BouncyCastle.X509.X509CertificateParser();
            Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[] { cp.ReadCertificate(x509.RawData) };
            IExternalSignature externalSignature = new X509Certificate2Signature(x509, "SHA1");
            //iTextSharp.text.Rectangle rect = getPosition(ref pro, pdfReader.GetPageSize(pro.pdfdetail.page));
            iTextSharp.text.Rectangle rect = new iTextSharp.text.Rectangle(100, 100, 200, 200);
            int count = reader.NumberOfPages;

            using (MemoryStream ms = new MemoryStream())
            {

                using (PdfStamper pdfStamper = PdfStamper.CreateSignature(reader, ms, '\0', null, true))
                {
                    PdfSignatureAppearance signatureAppearance = pdfStamper.SignatureAppearance;
                    signatureAppearance.SetVisibleSignature(rect, 1, "Signature" + DateTime.Now.ToFileTime().ToString());
                    signatureAppearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION;
                    signatureAppearance.Acro6Layers = false;
                    signatureAppearance.Layer4Text = PdfSignatureAppearance.questionMark;
                    MakeSignature.SignDetached(signatureAppearance, externalSignature, chain, null, null, null, 0, CryptoStandard.CADES);
                }
                by = ms.ToArray();

            }

            resp = Convert.ToBase64String(by);

            byte[] sPDFDecoded = Convert.FromBase64String(resp);
            System.IO.File.WriteAllBytes(outputFilePath, sPDFDecoded);
            Console.WriteLine("Pdf Signed Successfully.");
            Console.ReadLine();
        }
        public static void VerifySignature()
        {
            PdfReader reader = new PdfReader(@"D:\sinedpdf.pdf");

            // Get the signature dictionary
            AcroFields fields = reader.AcroFields;
            var signatureNames = fields.GetSignatureNames();
            string signatureName = signatureNames[0]; // Assuming there is only one signature

            PdfPKCS7 pkcs7 = fields.VerifySignature(signatureName);

            // Verify the signature
            if (pkcs7.Verify())
            {
                Console.WriteLine("Signature is valid.");
                Console.ReadLine();
            }
            else
            {
                Console.WriteLine("Signature is not valid.");
                Console.ReadLine();
            }
        }
        public static void SignMultiple()
        {
            try
            {


                //string resp = "";
                //byte[] by = null;
                //string inputFilePath = @"D:\simplepdf.pdf";
                //string outputFilePath = @"D:\sinedpdf1.pdf";
                //string PfxFilePath = @"D:\pfx\pfxfile.pfx";
                //PdfReader reader = new PdfReader(inputFilePath);
                ////byte[] data = Encoding.UTF8.GetBytes(PfxFilePath);

                //X509Certificate2 x509 = new X509Certificate2(PfxFilePath, "123");
                //Org.BouncyCastle.X509.X509CertificateParser cp = new Org.BouncyCastle.X509.X509CertificateParser();
                //Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[] { cp.ReadCertificate(x509.RawData) };
                //iTextSharp.text.Rectangle rect = new iTextSharp.text.Rectangle(100, 100, 200, 200);

                //using (reader)
                //{
                //    using (FileStream fileStream = new FileStream(outputFilePath, FileMode.Create))
                //    {
                //        using (PdfStamper stamper = PdfStamper.CreateSignature(reader, fileStream, '\0'))
                //        {
                //            for (int i = 1; i <= reader.NumberOfPages; i++)
                //            {
                //                // Perform signature on each page
                //                PdfSignatureAppearance appearance = stamper.SignatureAppearance;
                //                // Set signature appearance properties
                //                PdfSignatureAppearance signatureAppearance = stamper.SignatureAppearance;
                //                signatureAppearance.SetVisibleSignature(rect, i, "Signature" + DateTime.Now.ToFileTime().ToString());
                //                signatureAppearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION;
                //                signatureAppearance.Acro6Layers = false;
                //                signatureAppearance.Layer4Text = PdfSignatureAppearance.questionMark;
                //                ITSAClient tsaClient = new TSAClientBouncyCastle("http://timestamp.comodoca.com/rfc3161");
                //                IExternalSignature signature = new X509Certificate2Signature(x509, "SHA-256");
                //                MakeSignature.SignDetached(appearance, signature, chain, null, null, tsaClient, 0, CryptoStandard.CMS);
                //            }
                //            stamper.Close();
                //        }
                //    }
                //}


                //string inputFilePath = @"D:\simplepdf.pdf";
                //string outputFilePath = @"D:\sinedpdf1.pdf";
                //string PfxFilePath = @"D:\pfx\pfxfile.pfx";
                //PdfReader reader = new PdfReader(inputFilePath);

                //X509Certificate2 x509 = new X509Certificate2(PfxFilePath, "123");
                //Org.BouncyCastle.X509.X509CertificateParser cp = new Org.BouncyCastle.X509.X509CertificateParser();
                //Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[] { cp.ReadCertificate(x509.RawData) };
                //iTextSharp.text.Rectangle rect = new iTextSharp.text.Rectangle(100, 100, 200, 200);

                //using (reader)
                //{
                //    using (FileStream fileStream = new FileStream(outputFilePath, FileMode.Create))
                //    {
                //        using (PdfStamper stamper = PdfStamper.CreateSignature(reader, fileStream, '\0'))
                //        {
                //            for (int i = 1; i <= reader.NumberOfPages; i++)
                //            {
                //                // Perform signature on each page
                //                PdfSignatureAppearance appearance = stamper.SignatureAppearance;
                //                // Set signature appearance properties
                //                PdfSignatureAppearance signatureAppearance = stamper.SignatureAppearance;
                //                signatureAppearance.SetVisibleSignature(rect, i, "Signature" + DateTime.Now.ToFileTime().ToString());
                //                signatureAppearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION;
                //                signatureAppearance.Acro6Layers = false;
                //                signatureAppearance.Layer4Text = PdfSignatureAppearance.questionMark;
                //                ITSAClient tsaClient = new TSAClientBouncyCastle("http://timestamp.comodoca.com/rfc3161");
                //                IExternalSignature signature = new X509Certificate2Signature(x509, "SHA-256");
                //                MakeSignature.SignDetached(appearance, signature, chain, null, null, tsaClient, 0, CryptoStandard.CMS);
                //            }

                //            stamper.Close();

                //        }

                //        reader.Close();
                //    }
                //}




                //string inputFilePath = @"D:\simplepdf.pdf";
                //string outputFilePath = @"D:\sinedpdf1.pdf";
                //string PfxFilePath = @"D:\pfx\pfxfile.pfx";

                //X509Certificate2 x509 = new X509Certificate2(PfxFilePath, "123");
                //Org.BouncyCastle.X509.X509CertificateParser cp = new Org.BouncyCastle.X509.X509CertificateParser();
                //Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[] { cp.ReadCertificate(x509.RawData) };
                //iTextSharp.text.Rectangle rect = new iTextSharp.text.Rectangle(100, 100, 200, 200);

                //string inputFilePath = @"D:\simplepdf.pdf";
                //string PfxFilePath = @"D:\pfx\pfxfile.pfx";

                //X509Certificate2 x509 = new X509Certificate2(PfxFilePath, "123");
                //Org.BouncyCastle.X509.X509CertificateParser cp = new Org.BouncyCastle.X509.X509CertificateParser();
                //Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[] { cp.ReadCertificate(x509.RawData) };
                //iTextSharp.text.Rectangle rect = new iTextSharp.text.Rectangle(100, 100, 200, 200);

                //using (PdfReader reader = new PdfReader(inputFilePath))
                //{
                //    for (int i = 1; i <= reader.NumberOfPages; i++)
                //    {
                //        string outputFilePath = @"D:\signedpdf" + i + ".pdf";
                //        using (FileStream fileStream = new FileStream(outputFilePath, FileMode.Create))
                //        {
                //            using (PdfStamper stamper = PdfStamper.CreateSignature(reader, fileStream, '\0'))
                //            {
                //                // Perform signature on this page
                //                PdfSignatureAppearance appearance = stamper.SignatureAppearance;
                //                // Set signature appearance properties
                //                PdfSignatureAppearance signatureAppearance = stamper.SignatureAppearance;
                //                signatureAppearance.SetVisibleSignature(rect, i, "Signature" + DateTime.Now.ToFileTime().ToString());
                //                signatureAppearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION;
                //                signatureAppearance.Acro6Layers = false;
                //                signatureAppearance.Layer4Text = PdfSignatureAppearance.questionMark;
                //                ITSAClient tsaClient = new TSAClientBouncyCastle("http://timestamp.comodoca.com/rfc3161");
                //                IExternalSignature signature = new X509Certificate2Signature(x509, "SHA-256");
                //                MakeSignature.SignDetached(appearance, signature, chain, null, null, tsaClient, 0, CryptoStandard.CMS);
                //            }
                //        }
                //    }
                //    reader.Close();
                //}

                //string inputFilePath = @"D:\simplepdf.pdf";
                //string outputFilePath = @"D:\signedpdf1.pdf";
                //string PfxFilePath = @"D:\pfx\pfxfile.pfx";

                //X509Certificate2 x509 = new X509Certificate2(PfxFilePath, "123");
                //Org.BouncyCastle.X509.X509CertificateParser cp = new Org.BouncyCastle.X509.X509CertificateParser();
                //Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[] { cp.ReadCertificate(x509.RawData) };
                //iTextSharp.text.Rectangle rect = new iTextSharp.text.Rectangle(100, 100, 200, 200);

                //PdfStamper stamper = PdfStamper.CreateSignature(new PdfReader(inputFilePath), new FileStream(outputFilePath, FileMode.Create), '\0');

                //for (int i = 1; i <= stamper.Reader.NumberOfPages; i++)
                //{
                //    // Perform signature on each page
                //    PdfSignatureAppearance appearance = stamper.SignatureAppearance;
                //    // Set signature appearance properties
                //    PdfSignatureAppearance signatureAppearance = stamper.SignatureAppearance;
                //    signatureAppearance.SetVisibleSignature(rect, i, "Signature" + DateTime.Now.ToFileTime().ToString());
                //    signatureAppearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION;
                //    signatureAppearance.Acro6Layers = false;
                //    signatureAppearance.Layer4Text = PdfSignatureAppearance.questionMark;
                //    ITSAClient tsaClient = new TSAClientBouncyCastle("http://timestamp.comodoca.com/rfc3161");
                //    IExternalSignature signature = new X509Certificate2Signature(x509, "SHA-256");
                //    MakeSignature.SignDetached(appearance, signature, chain, null, null, tsaClient, 0, CryptoStandard.CMS);
                //}

                // Close the PdfStamper object after all signatures have been added
                //stamper.Close();




                //// Load the PDF document
                //PdfReader reader = new PdfReader(@"D:\simplepdf1.pdf");

                //// Create the output stream for the signed PDF
                //using (FileStream outputStream = new FileStream(@"D:\signedpdf1.pdf", FileMode.Create))
                //{
                //    // Create a PDF stamper to apply the digital signature
                //    PdfStamper stamper = PdfStamper.CreateSignature(reader, outputStream, '\0');

                //    // Load the PFX file
                //    X509Certificate2 certificate = new X509Certificate2(@"D:\pfx\pfxfile.pfx", "123");
                //    Org.BouncyCastle.X509.X509CertificateParser cp = new Org.BouncyCastle.X509.X509CertificateParser();
                //    Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[] { cp.ReadCertificate(certificate.RawData) };

                //    //Set the signature encryption level

                //    for (int i = 1; i <= stamper.Reader.NumberOfPages; i++)
                //    {
                //        File.Delete(@"D:\sinedpdf1.pdf");
                //        PdfSignatureAppearance signatureAppearance = stamper.SignatureAppearance;
                //        signatureAppearance.SetVisibleSignature(new Rectangle(100, 100, 200, 200), i, "Signature"+i);
                //        // Create the signature object
                //        PdfSignature signature = new PdfSignature(PdfName.ADOBE_PPKMS, PdfName.ADBE_PKCS7_SHA1);
                //        signature.Name = "Digital signature";
                //        signature.Reason = "Document signed with iTextSharp";
                //        signature.Location = "Worldwide";
                //        // Create the signature container
                //        IExternalSignature externalSignature = new X509Certificate2Signature(certificate, "SHA-1");
                //        MakeSignature.SignDetached(signatureAppearance, externalSignature, chain, null, null, null, 0, CryptoStandard.CMS);
                //    }
                //    // Close the stamper and reader
                //    stamper.Close();
                //    reader.Close();
                //}



                //using (var inputPdfStream = new FileStream(@"D:\simplepdf.pdf", FileMode.Open))
                //{
                //    // Create the output PDF file
                //    using (var outputPdfStream = new FileStream(@"D:\signedpdf1.pdf", FileMode.Create))
                //    {
                //        // Create a PDF reader and a PDF stamper
                //        var reader = new PdfReader(inputPdfStream);
                //        var stamper = PdfStamper.CreateSignature(reader, outputPdfStream, '\0', null, true);

                //        // Load the PFX file
                //        var pfxBytes = File.ReadAllBytes(@"D:\pfx\pfxfile.pfx");
                //        var pfx = new Org.BouncyCastle.Pkcs.Pkcs12Store(new MemoryStream(pfxBytes), "123".ToCharArray());

                //        // Get the private key and certificate from the PFX file
                //        var alias = pfx.Aliases.Cast<string>().FirstOrDefault(x => pfx.IsKeyEntry(x));
                //        var privateKey = pfx.GetKey(alias).Key;

                //        X509Certificate2 x509 = new X509Certificate2(@"D:\pfx\pfxfile.pfx", "123");
                //        Org.BouncyCastle.X509.X509CertificateParser cp = new Org.BouncyCastle.X509.X509CertificateParser();
                //        Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[] { cp.ReadCertificate(x509.RawData) };

                //        for (int i = 1; i <= stamper.Reader.NumberOfPages; i++)
                //        {
                //            // Create a signature appearance
                //            var signatureAppearance = stamper.SignatureAppearance;
                //            signatureAppearance.SetVisibleSignature(new Rectangle(100, 100, 200, 200), i, null);

                //            // Set the signing certificate and private key
                //            var externalSignature = new PrivateKeySignature(privateKey, "SHA-256");
                //            MakeSignature.SignDetached(signatureAppearance, externalSignature, chain, null, null, null, 0, CryptoStandard.CMS);
                //        }

                //        // Save the output PDF file
                //        stamper.Close();
                //        reader.Close();
                //        reader.Dispose();
                //    }
                //}

                // Load the PDF document


                //string inputFilePath = @"D:\simplepdf.pdf";
                //string outputFilePath = @"D:\signedpdf\sinedpdf1.pdf";
                //string PfxFilePath = @"D:\pfx\pfxfile.pfx";

                //X509Certificate2 x509 = new X509Certificate2(PfxFilePath, "123");
                //Org.BouncyCastle.X509.X509CertificateParser cp = new Org.BouncyCastle.X509.X509CertificateParser();
                //Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[] { cp.ReadCertificate(x509.RawData) };
                //iTextSharp.text.Rectangle rect = new iTextSharp.text.Rectangle(100, 100, 200, 200);

                //using (FileStream fileStream = new FileStream(outputFilePath, FileMode.Create))
                //{
                //    using (PdfStamper stamper = PdfStamper.CreateSignature(new PdfReader(inputFilePath), fileStream, '\0'))
                //    {
                //        for (int i = 1; i <= stamper.Reader.NumberOfPages; i++)
                //        {

                //            File.Delete(outputFilePath);                       
                //            // Perform signature on each page
                //            PdfSignatureAppearance appearance = stamper.SignatureAppearance;
                //            // Set signature appearance properties
                //            PdfSignatureAppearance signatureAppearance = stamper.SignatureAppearance;
                //            signatureAppearance.SetVisibleSignature(rect, i, "Signature" + DateTime.Now.ToFileTime().ToString());
                //            signatureAppearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION;
                //            signatureAppearance.Acro6Layers = false;
                //            signatureAppearance.Layer4Text = PdfSignatureAppearance.questionMark;
                //            ITSAClient tsaClient = new TSAClientBouncyCastle("http://timestamp.comodoca.com/rfc3161");
                //            IExternalSignature signature = new X509Certificate2Signature(x509, "SHA-256");
                //            MakeSignature.SignDetached(appearance, signature, chain, null, null, tsaClient, 0, CryptoStandard.CMS);
                //        }

                //    }

                //}   

                byte[] by = null;
                string inputFilePath = @"D:\simplepdf.pdf";
                string PfxFilePath = @"D:\pfx\pfxfile.pfx";
                string resp = "";
                PdfReader reader = new PdfReader(inputFilePath);
                //byte[] data = Encoding.UTF8.GetBytes(PfxFilePath);

                X509Certificate2 x509 = new X509Certificate2(PfxFilePath, "123");
                Org.BouncyCastle.X509.X509CertificateParser cp = new Org.BouncyCastle.X509.X509CertificateParser();
                Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[] { cp.ReadCertificate(x509.RawData) };
                IExternalSignature externalSignature = new X509Certificate2Signature(x509, "SHA1");
                //iTextSharp.text.Rectangle rect = getPosition(ref pro, pdfReader.GetPageSize(pro.pdfdetail.page));
                iTextSharp.text.Rectangle rect = new iTextSharp.text.Rectangle(100, 100, 200, 200);
                int count = reader.NumberOfPages;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (PdfStamper pdfStamper = PdfStamper.CreateSignature(reader, ms, '\0', null, true))
                    {
                        PdfSignatureAppearance signatureAppearance = pdfStamper.SignatureAppearance;
                        signatureAppearance.SetVisibleSignature(rect, count, "Signature" + DateTime.Now.ToFileTime().ToString());
                        signatureAppearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION;
                        signatureAppearance.Acro6Layers = false;
                        signatureAppearance.Layer4Text = PdfSignatureAppearance.questionMark;
                        MakeSignature.SignDetached(signatureAppearance, externalSignature, chain, null, null, null, 0, CryptoStandard.CADES);
                    }
                    by = ms.ToArray();

                }
                if (count > 1)
                {
                    BulkSign(by, count);
                }
                else
                {
                    resp = Convert.ToBase64String(by);
                    byte[] sPDFDecoded = Convert.FromBase64String(resp);
                    System.IO.File.WriteAllBytes(@"D:\sinedpdf1.pdf", sPDFDecoded);
                    Console.WriteLine("Pdf Signed Successfully.");
                    Console.ReadLine();
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine("error:-" + ex.Message);
                Console.ReadLine();
            }
        }
        public static void BulkSign(byte[] by, int count)
        {
            string resp = "";
            string PfxFilePath = @"D:\pfx\pfxfile.pfx";
            PdfReader reader = new PdfReader(by);    
            X509Certificate2 x509 = new X509Certificate2(PfxFilePath, "123");
            Org.BouncyCastle.X509.X509CertificateParser cp = new Org.BouncyCastle.X509.X509CertificateParser();
            Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[] { cp.ReadCertificate(x509.RawData) };
            IExternalSignature externalSignature = new X509Certificate2Signature(x509, "SHA1");
            //iTextSharp.text.Rectangle rect = getPosition(ref pro, pdfReader.GetPageSize(pro.pdfdetail.page));
            iTextSharp.text.Rectangle rect = new iTextSharp.text.Rectangle(100, 100, 200, 200);
         
            using (MemoryStream ms = new MemoryStream())
            {
                using (PdfStamper pdfStamper = PdfStamper.CreateSignature(reader, ms, '\0', null, true))
                {
                    PdfSignatureAppearance signatureAppearance = pdfStamper.SignatureAppearance;
                    signatureAppearance.SetVisibleSignature(rect, count, "Signature" + DateTime.Now.ToFileTime().ToString());
                    signatureAppearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION;
                    signatureAppearance.Acro6Layers = false;
                    signatureAppearance.Layer4Text = PdfSignatureAppearance.questionMark;
                    MakeSignature.SignDetached(signatureAppearance, externalSignature, chain, null, null, null, 0, CryptoStandard.CADES);
                }
                by = ms.ToArray();
                count--;
            }
            if (count > 0)
            {
                BulkSign(by, count);
            }
            else
            {
                resp = Convert.ToBase64String(by);
                byte[] sPDFDecoded = Convert.FromBase64String(resp);
                System.IO.File.WriteAllBytes(@"D:\sinedpdf1.pdf", sPDFDecoded);
                Console.WriteLine("Pdf Signed Successfully.");
                Console.ReadLine();
            }

        }
    }

}
