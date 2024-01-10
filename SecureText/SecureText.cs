using Bunifu.UI.WinForms;
using SecureText.Classes;
using System;
using System.ComponentModel;
using System.Windows.Forms;

namespace SecureText
{
    public partial class SecureText : Form
    {
        string RawData = null;
        string Password = null;

        string Procedure = null;

        string EncryptedData = null;
        string DecryptedData = null;

        int CharactersCount = 0;

        public SecureText()
        {
            InitializeComponent();
            this.Icon = Properties.Resources.Icon;
        }

        private const int CS_DROPSHADOW = 0x00020000;
        protected override CreateParams CreateParams
        {
            get
            {
                CreateParams cp = base.CreateParams;
                cp.ClassStyle |= CS_DROPSHADOW;
                return cp;
            }
        }

        private void SecureText_Load(object sender, EventArgs e)
        {

        }

        private void btnGeneratePassword_Click(object sender, EventArgs e)
        {
            if (cboProcedure.Text == "AES-256")
            {
                txtPassword.Text = GeneratePassword.AESPassword();
            }

            else if (cboProcedure.Text == "Triple DES (2 rounds)")
            {
                txtPassword.Text = GeneratePassword.TwoPasswords();
            }

            else if (cboProcedure.Text == "Triple DES (4 rounds)")
            {
                txtPassword.Text = GeneratePassword.FourPasswords();
            }

            else
                txtPassword.Text = GeneratePassword.Generate();
        }

        private void btnClose_Click(object sender, EventArgs e)
        {
            if (bgwEncrypt.IsBusy || bgwDecrypt.IsBusy)
            {
                sbMessage.Show(this, "Wait for the end of the operation!", BunifuSnackbar.MessageTypes.Warning,
                duration: 3000, position: BunifuSnackbar.Positions.TopCenter);
            }

            else
                Environment.Exit(0);
        }

        private void btnCopy_Click(object sender, EventArgs e)
        {
            if (!string.IsNullOrEmpty(txtText.Text))
            {
                Clipboard.SetText(txtText.Text);
                sbMessage.Show(this, "Text copied!", BunifuSnackbar.MessageTypes.Success,
                duration: 3000, position: BunifuSnackbar.Positions.TopCenter);
            }  
        }

        private void btnEncrypt_Click(object sender, EventArgs e)
        {
            if(!string.IsNullOrEmpty(cboProcedure.Text) && !string.IsNullOrEmpty(txtText.Text))
            {
                RawData = txtText.Text;
                Password = txtPassword.Text;

                btnEncrypt.Enabled = false;
                btnDecrypt.Enabled = false;
                btnCopy.Enabled = false;

                txtPassword.PasswordChar = '*';

                bgwEncrypt.RunWorkerAsync();
            }

            else
            {
                sbMessage.Show(this, "Fill all necessary fields!", BunifuSnackbar.MessageTypes.Warning,
                    duration: 3000, position: BunifuSnackbar.Positions.TopCenter);

                RawData = null;
                Password = null;
            }
                
        }

        private void btnDecrypt_Click(object sender, EventArgs e)
        {
            if (!string.IsNullOrEmpty(cboProcedure.Text) && !string.IsNullOrEmpty(txtText.Text))
            {
                RawData = txtText.Text;
                Password = txtPassword.Text;

                btnEncrypt.Enabled = false;
                btnDecrypt.Enabled = false;
                btnCopy.Enabled = false;

                txtPassword.PasswordChar = '*';

                bgwDecrypt.RunWorkerAsync();
            }
                
            else
            {
                sbMessage.Show(this, "Fill all necessary fields!", BunifuSnackbar.MessageTypes.Warning,
                    duration: 3000, position: BunifuSnackbar.Positions.TopCenter);

                RawData = null;
                Password = null;
            }     
        }

        private void bgwEncrypt_DoWork(object sender, DoWorkEventArgs e)
        {
            switch (Procedure)
            {
                case "AES-256":
                    EncryptedData = Encryptor.AESEncryption(RawData, Password);
                    break;

                case "Triple DES":
                    EncryptedData = Encryptor.TripleDESEncryption(RawData, Password);
                    break;

                case "Extended Triple DES":
                    EncryptedData = Encryptor.ExtendedTripleDESEncryption(RawData, Password);
                    break;
                
                case "Triple DES (2 rounds)":
                    EncryptedData = Encryptor.TripleDES2RoundsEncryption(RawData, Password);
                    break;

                case "Triple DES (4 rounds)":
                    EncryptedData = Encryptor.TripleDES4RoundsEncryption(RawData, Password);
                    break;

                case "RC4":
                    EncryptedData = Encryptor.RC4Encryption(RawData, Password);
                    break;

                case "ROT13":
                    EncryptedData = Encryptor.ROT13Encryption(RawData);
                    break;

                case "Base64":
                    EncryptedData = Encryptor.Base64Encryption(RawData);
                    break;

                default:
                    break;
            }
        }

        private void bgwEncrypt_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            txtText.Clear();

            txtText.Text = EncryptedData;

            RawData = null;
            Password = null;

            EncryptedData = null;
            DecryptedData = null;

            btnEncrypt.Enabled = true;
            btnDecrypt.Enabled = true;
            btnCopy.Enabled = true;

            if (CharactersCount >= txtText.MaxLength)
            {
                sbMessage.Show(this, "The maximum text size has been reached. Data will be deleted!", BunifuSnackbar.MessageTypes.Warning,
                    duration: 3000, position: BunifuSnackbar.Positions.TopCenter);
                txtText.Clear();
            }
            else if (txtText.Text.Length == 0)
            {
                sbMessage.Show(this, "Something went wrong! Please, check the input parameters!", 
                    BunifuSnackbar.MessageTypes.Error, duration: 3000, 
                    position: BunifuSnackbar.Positions.TopCenter);
            }
            else if(CharactersCount < txtText.MaxLength)
            {
                sbMessage.Show(this, "Successfully encrypted!", BunifuSnackbar.MessageTypes.Success,
                duration: 3000, position: BunifuSnackbar.Positions.TopCenter);
            }
        }

        private void bgwDecrypt_DoWork(object sender, DoWorkEventArgs e)
        {
            switch (Procedure)
            {
                case "AES-256":
                    DecryptedData = Decryptor.AESDecryption(RawData, Password);
                    break;

                case "Triple DES":
                    DecryptedData = Decryptor.TripleDESDecryption(RawData, Password);
                    break;

                case "Extended Triple DES":
                    DecryptedData = Decryptor.ExtendedTripleDESDecryption(RawData, Password);
                    break;

                case "Triple DES (2 rounds)":
                    DecryptedData = Decryptor.TripleDES2RoundsDecryption(RawData, Password);
                    break;

                case "Triple DES (4 rounds)":
                    DecryptedData = Decryptor.TripleDES4RoundsDecryption(RawData, Password);
                    break;

                case "RC4":
                    DecryptedData = Decryptor.RC4Decryption(RawData, Password);
                    break;

                case "ROT13":
                    DecryptedData = Decryptor.ROT13Decryption(RawData);
                    break;

                case "Base64":
                    DecryptedData = Decryptor.Base64Decryption(RawData);
                    break;

                default:
                    break;
            }
        }

        private void bgwDecrypt_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            txtText.Clear();

            txtText.Text = DecryptedData;

            RawData = null;
            Password = null;

            EncryptedData = null;
            DecryptedData = null;

            btnEncrypt.Enabled = true;
            btnDecrypt.Enabled = true;
            btnCopy.Enabled = true;

            if (CharactersCount >= txtText.MaxLength)
            {
                sbMessage.Show(this, "The maximum text size has been reached. Data will be deleted!", BunifuSnackbar.MessageTypes.Warning,
                    duration: 3000, position: BunifuSnackbar.Positions.TopCenter);
                txtText.Clear();
            }
            else if (txtText.Text.Length == 0)
            {
                sbMessage.Show(this, "Something went wrong! Please, check the input parameters!",
                    BunifuSnackbar.MessageTypes.Error, duration: 3000,
                    position: BunifuSnackbar.Positions.TopCenter);
            }
            else if (CharactersCount < txtText.MaxLength)
            {
                sbMessage.Show(this, "Successfully decrypted!", BunifuSnackbar.MessageTypes.Success,
                duration: 3000, position: BunifuSnackbar.Positions.TopCenter);
            }
        }

        private void cboProcedure_SelectedIndexChanged(object sender, EventArgs e)
        {
            Procedure = cboProcedure.Text;

            if (cboProcedure.Text == "ROT13" || cboProcedure.Text == "Base64")
            {
                sbMessage.Show(this, "This algorithm do not require a password!",
                    BunifuSnackbar.MessageTypes.Information, duration: 3000,
                    position: BunifuSnackbar.Positions.TopCenter);

                txtPassword.Clear();
                txtPassword.Enabled = false;
                btnGeneratePassword.Enabled = false;
            }

            else
            {
                txtPassword.Clear();
                txtPassword.Enabled = true;
                btnGeneratePassword.Enabled = true;
            }
        }

        private void txtText_TextChanged(object sender, EventArgs e)
        {
            CharactersCount = txtText.TextLength;

            if (CharactersCount >= txtText.MaxLength)
            {
                sbMessage.Show(this, "Maximum text size reached!", BunifuSnackbar.MessageTypes.Warning,
                    duration: 3000, position: BunifuSnackbar.Positions.TopCenter);
            }
        }

        private void txtPassword_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            if (!string.IsNullOrEmpty(txtPassword.Text))
            {
                Clipboard.SetText(txtPassword.Text);
                sbMessage.Show(this, "Password copied!", BunifuSnackbar.MessageTypes.Success,
                duration: 3000, position: BunifuSnackbar.Positions.TopCenter);
            }
        }

        private void txtText_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            if (!string.IsNullOrEmpty(txtText.Text))
            {
                Clipboard.SetText(txtText.Text);
                sbMessage.Show(this, "Data copied!", BunifuSnackbar.MessageTypes.Success,
                duration: 3000, position: BunifuSnackbar.Positions.TopCenter);
            }
        }

        private void txtPassword_MouseHover(object sender, EventArgs e)
        {
            txtPassword.PasswordChar = '\0';
        }

        private void txtPassword_MouseLeave(object sender, EventArgs e)
        {
            txtPassword.PasswordChar = '*';
        }
    }
}
