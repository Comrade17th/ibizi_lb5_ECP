using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
 
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.IO;

namespace ibizi_lb5
{
    class Program
    {
        static void Main(string[] args)
        {
        }

        private FileObj Decript(FileObj file_obj)
        {
            string fileName = file_obj.fileAndParams.FileName;
            try
            {
                Cryption crypt = new Cryption("Имя Человека котором принадлежит Сертификат");
                Files f = new Files();
                byte[] decripted = null;
                byte[] withOutHeaders = null;
                byte[] decode_b64 = null;
                //сохраняем полученныей файл в папку ECP
                if (!Directory.Exists(main_obj.mailPath + @"\ECP\"))
                {
                    System.IO.Directory.CreateDirectory(main_obj.mailPath + @"\ECP\");
                }

                string fileFullPath = main_obj.mailPath + @"\ECP\" + fileName;
                SaveFile(fileFullPath, file_obj.fileAndParams.FileBody, 0, false);

                if ((Regex.Match(fileName, @".*?\.sig\.enc\z", RegexOptions.IgnoreCase)).Success || (Regex.Match(fileName, @".*?\.p7s\.p7m\z", RegexOptions.IgnoreCase)).Success)
                {
                    if (crypt.DetectBase64Encode(file_obj.fileAndParams.FileBody))
                    {
                        // file_obj.fileAndParams.FileBody = f.FileReadToBytes(fileFullPath);
                        withOutHeaders = crypt.RemovePkcsHeaders(file_obj.fileAndParams.FileBody);
                        decode_b64 = crypt.Base64Decode(withOutHeaders);
                        decripted = crypt.UnsignedByRecipentCertificate(decode_b64);
                    }
                    else
                    {
                        decode_b64 = crypt.Decode(file_obj.fileAndParams.FileBody);
                        decripted = crypt.Unsign(decode_b64);
                    }
                    fileName = fileName.Substring(0, fileName.LastIndexOf('.'));
                    fileName = fileName.Substring(0, fileName.LastIndexOf('.'));
                }
                else if ((Regex.Match(fileName, @".*?\.enc\.sig\z", RegexOptions.IgnoreCase)).Success || (Regex.Match(fileName, @".*?\.p7m\.p7s\z", RegexOptions.IgnoreCase)).Success)
                {
                    if (crypt.DetectBase64Encode(file_obj.fileAndParams.FileBody))
                    {
                        // file_obj.fileAndParams.FileBody = f.FileReadToBytes(fileFullPath);
                        withOutHeaders = crypt.RemovePkcsHeaders(file_obj.fileAndParams.FileBody);
                        decode_b64 = crypt.Base64Decode(withOutHeaders);
                        decripted = crypt.Base64Decode(decode_b64);

                    }
                    else
                    {
                        decode_b64 = crypt.Unsign(file_obj.fileAndParams.FileBody);
                        decripted = crypt.Decode(decode_b64);
                    }
                    fileName = fileName.Substring(0, fileName.LastIndexOf('.'));
                    fileName = fileName.Substring(0, fileName.LastIndexOf('.'));
                }
                else if ((Regex.Match(fileName, @".*?\.enc\z", RegexOptions.IgnoreCase)).Success || (Regex.Match(fileName, @".*?\.p7m\z", RegexOptions.IgnoreCase)).Success)
                {
                    if (crypt.DetectBase64Encode(file_obj.fileAndParams.FileBody))
                    {
                        // file_obj.fileAndParams.FileBody = f.FileReadToBytes(fileFullPath);
                        withOutHeaders = crypt.RemovePkcsHeaders(file_obj.fileAndParams.FileBody);
                        decode_b64 = crypt.Base64Decode(withOutHeaders);
                        decripted = decode_b64;
                    }
                    else
                    {
                        decode_b64 = crypt.Decode(file_obj.fileAndParams.FileBody);
                        decripted = decode_b64;
                    }
                    fileName = fileName.Substring(0, fileName.LastIndexOf('.'));
                }
                else if ((Regex.Match(fileName, @".*?\.sig\z", RegexOptions.IgnoreCase)).Success || (Regex.Match(fileName, @".*?\.p7s\z", RegexOptions.IgnoreCase)).Success)
                {
                    if (crypt.DetectBase64Encode(file_obj.fileAndParams.FileBody))
                    {
                        // file_obj.fileAndParams.FileBody = f.FileReadToBytes(fileFullPath);
                        withOutHeaders = crypt.RemovePkcsHeaders(file_obj.fileAndParams.FileBody);
                        decode_b64 = crypt.UnsignedByRecipentCertificate(withOutHeaders);
                        decripted = decode_b64;
                    }
                    else
                    {
                        decode_b64 = crypt.Unsign(file_obj.fileAndParams.FileBody);
                        decripted = decode_b64;
                    }
                    fileName = fileName.Substring(0, fileName.LastIndexOf('.'));
                }
                else
                {
                    li_log.Add_to_log_file_error(DateTime.Now + @" Ошибка! Файл " + fileFullPath + " переданный на дешифрование не прошел ФЛК.", main_obj.MailErrWarn);
                }

                FileObj newfileObj = new FileObj(li_log, main_obj.MailErrWarn, new FileAndParams()
                {
                    FileBody = decripted,
                    FileName = fileName
                });

                return newfileObj;
            }
            catch (Exception e)
            {
                if (e.Message.Contains("не указан получатель"))
                {
                    li_log.Add_to_log_file_warning(DateTime.Now + @" Предупреждение: При обработки файла " + file_obj.fileAndParams.FileName + " возникла ошибка BAD_ECP! Текст ошибки:"
                                                   + e.Message, main_obj.MailErrWarn);
                }
                else
                {
                    li_log.Add_to_log_file_error(DateTime.Now + @" Ошибка: При обработки файла " + file_obj.fileAndParams.FileName + " возникла ошибка BAD_ECP! Текст ошибки:"
                                                 + e.Message, main_obj.MailErrWarn);
                }

                System.IO.Directory.CreateDirectory(main_obj.li_settings.FolderInbox + @"\BAD_ECP\");
                string fileFullPath = main_obj.li_settings.FolderInbox + @"\BAD_ECP\" + fileName;
                SaveFile(fileFullPath, file_obj.fileAndParams.FileBody, 0, true);

                return null;
            }
        }
    }
}
