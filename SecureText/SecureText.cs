using Bunifu.UI.WinForms;
using SecureText.Classes;
using System;
using System.ComponentModel;
using System.Windows.Forms;

namespace SecureText
{
    public partial class SecureText : Form
    {
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
                bgwEncrypt.RunWorkerAsync();
            else
                sbMessage.Show(this, "Fill all necessary fields!", BunifuSnackbar.MessageTypes.Warning,
                    duration: 3000, position: BunifuSnackbar.Positions.TopCenter);
        }

        private void btnDecrypt_Click(object sender, EventArgs e)
        {
            if (!string.IsNullOrEmpty(cboProcedure.Text) && !string.IsNullOrEmpty(txtText.Text))
                bgwDecrypt.RunWorkerAsync();
            else
                sbMessage.Show(this, "Fill all necessary fields!", BunifuSnackbar.MessageTypes.Warning,
                    duration: 3000, position: BunifuSnackbar.Positions.TopCenter);
        }



        private void bgwEncrypt_DoWork(object sender, DoWorkEventArgs e)
        {
            btnEncrypt.Enabled = false;
            btnDecrypt.Enabled = false;
            btnCopy.Enabled = false;

            switch (Procedure)
            {
                case "Triple DES algorithm":
                    EncryptedData = Encryptor.TripleDESEncryption(txtText.Text, txtPassword.Text);
                    break;

                case "Binary Triple DES algorithm":
                    EncryptedData = Encryptor.BinaryTripleDESEncryption(txtText.Text, txtPassword.Text);
                    break;

                case "Extended TripleDES algorithm":
                    EncryptedData = Encryptor.ExtendedTripleDESEncryption(txtText.Text, txtPassword.Text);
                    break;

                case "ROT13 algorithm":
                    EncryptedData = Encryptor.ROT13Encryption(txtText.Text);
                    break;

                case "Binary algorithm":
                    EncryptedData = Encryptor.BinaryDecryption(txtText.Text);
                    break;

                default:
                    break;
            }
        }

        private void bgwEncrypt_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            txtText.Clear();
            txtPassword.Clear();
            txtText.Text = EncryptedData;

            btnEncrypt.Enabled = true;
            btnDecrypt.Enabled = true;
            btnCopy.Enabled = true;

            if (CharactersCount >= txtText.MaxLength)
            {
                sbMessage.Show(this, "The maximum text size has been reached. Data will be deleted!", BunifuSnackbar.MessageTypes.Warning,
                    duration: 3000, position: BunifuSnackbar.Positions.TopCenter);
                txtText.Clear();
            }
            else if (CharactersCount < txtText.MaxLength)
            {
                sbMessage.Show(this, "Successfully encrypted!", BunifuSnackbar.MessageTypes.Success,
                duration: 3000, position: BunifuSnackbar.Positions.TopCenter);
            }
        }



        private void bgwDecrypt_DoWork(object sender, DoWorkEventArgs e)
        {
            btnEncrypt.Enabled = false;
            btnDecrypt.Enabled = false;
            btnCopy.Enabled = false;

            switch (Procedure)
            {
                case "Triple DES algorithm":
                    DecryptedData = Decryptor.TripleDESDecryption(txtText.Text, txtPassword.Text);
                    break;

                case "Binary Triple DES algorithm":
                    DecryptedData = Decryptor.BinaryTripleDESEncryption(txtText.Text, txtPassword.Text);
                    break;

                case "Extended TripleDES algorithm":
                    DecryptedData = Decryptor.ExtendedTripleDESDecryption(txtText.Text, txtPassword.Text);
                    break;

                case "ROT13 algorithm":
                    DecryptedData = Decryptor.ROT13Decryption(txtText.Text);
                    break;

                case "Binary algorithm":
                    DecryptedData = Decryptor.BinaryDecryption(txtText.Text);
                    break;

                default:
                    break;
            }
        }

        private void bgwDecrypt_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            txtText.Clear();
            txtPassword.Clear();
            txtText.Text = DecryptedData;

            btnEncrypt.Enabled = true;
            btnDecrypt.Enabled = true;
            btnCopy.Enabled = true;

            if (CharactersCount >= txtText.MaxLength)
            {
                sbMessage.Show(this, "The maximum text size has been reached. Data will be deleted!", BunifuSnackbar.MessageTypes.Warning,
                    duration: 3000, position: BunifuSnackbar.Positions.TopCenter);
                txtText.Clear();
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

            if (cboProcedure.Text == "ROT13 algorithm" || cboProcedure.Text == "Binary algorithm")
            {
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

            lblCount.Text = CharactersCount.ToString();

            if (CharactersCount >= txtText.MaxLength)
            {
                sbMessage.Show(this, "Maximum text size reached!", BunifuSnackbar.MessageTypes.Warning,
                    duration: 3000, position: BunifuSnackbar.Positions.TopCenter);
            }
        }
    }
}
