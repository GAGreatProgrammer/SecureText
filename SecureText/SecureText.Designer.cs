﻿
namespace SecureText
{
    partial class SecureText
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(SecureText));
            Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderEdges borderEdges1 = new Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderEdges();
            Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderEdges borderEdges2 = new Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderEdges();
            Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderEdges borderEdges3 = new Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderEdges();
            Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderEdges borderEdges4 = new Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderEdges();
            Bunifu.UI.WinForms.BunifuTextBox.StateProperties stateProperties1 = new Bunifu.UI.WinForms.BunifuTextBox.StateProperties();
            Bunifu.UI.WinForms.BunifuTextBox.StateProperties stateProperties2 = new Bunifu.UI.WinForms.BunifuTextBox.StateProperties();
            Bunifu.UI.WinForms.BunifuTextBox.StateProperties stateProperties3 = new Bunifu.UI.WinForms.BunifuTextBox.StateProperties();
            Bunifu.UI.WinForms.BunifuTextBox.StateProperties stateProperties4 = new Bunifu.UI.WinForms.BunifuTextBox.StateProperties();
            this.bunifuLabel3 = new Bunifu.UI.WinForms.BunifuLabel();
            this.bunifuLabel2 = new Bunifu.UI.WinForms.BunifuLabel();
            this.bunifuLabel1 = new Bunifu.UI.WinForms.BunifuLabel();
            this.cboProcedure = new Bunifu.UI.WinForms.BunifuDropdown();
            this.bunifuLabel5 = new Bunifu.UI.WinForms.BunifuLabel();
            this.bunifuLabel4 = new Bunifu.UI.WinForms.BunifuLabel();
            this.bunifuLabel6 = new Bunifu.UI.WinForms.BunifuLabel();
            this.Elipse = new Bunifu.Framework.UI.BunifuElipse(this.components);
            this.btnClose = new Bunifu.UI.WinForms.BunifuImageButton();
            this.btnDecrypt = new Bunifu.UI.WinForms.BunifuButton.BunifuButton2();
            this.btnCopy = new Bunifu.UI.WinForms.BunifuButton.BunifuButton2();
            this.btnEncrypt = new Bunifu.UI.WinForms.BunifuButton.BunifuButton2();
            this.btnGeneratePassword = new Bunifu.UI.WinForms.BunifuButton.BunifuButton2();
            this.txtPassword = new Bunifu.UI.WinForms.BunifuTextBox();
            this.bgwEncrypt = new System.ComponentModel.BackgroundWorker();
            this.bgwDecrypt = new System.ComponentModel.BackgroundWorker();
            this.DragControl = new Bunifu.Framework.UI.BunifuDragControl(this.components);
            this.sbMessage = new Bunifu.UI.WinForms.BunifuSnackbar(this.components);
            this.txtText = new System.Windows.Forms.RichTextBox();
            this.UserControl = new Bunifu.UI.WinForms.BunifuUserControl();
            this.SuspendLayout();
            // 
            // bunifuLabel3
            // 
            this.bunifuLabel3.AllowParentOverrides = false;
            this.bunifuLabel3.AutoEllipsis = false;
            this.bunifuLabel3.Cursor = System.Windows.Forms.Cursors.Default;
            this.bunifuLabel3.CursorType = System.Windows.Forms.Cursors.Default;
            this.bunifuLabel3.Font = new System.Drawing.Font("Segoe UI", 12F, System.Drawing.FontStyle.Bold);
            this.bunifuLabel3.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.bunifuLabel3.Location = new System.Drawing.Point(175, 30);
            this.bunifuLabel3.Name = "bunifuLabel3";
            this.bunifuLabel3.RightToLeft = System.Windows.Forms.RightToLeft.No;
            this.bunifuLabel3.Size = new System.Drawing.Size(222, 21);
            this.bunifuLabel3.TabIndex = 5;
            this.bunifuLabel3.Text = "Encrypt & Decrypt text easily";
            this.bunifuLabel3.TextAlignment = System.Drawing.ContentAlignment.TopLeft;
            this.bunifuLabel3.TextFormat = Bunifu.UI.WinForms.BunifuLabel.TextFormattingOptions.Default;
            // 
            // bunifuLabel2
            // 
            this.bunifuLabel2.AllowParentOverrides = false;
            this.bunifuLabel2.AutoEllipsis = false;
            this.bunifuLabel2.CursorType = null;
            this.bunifuLabel2.Font = new System.Drawing.Font("Segoe UI", 20.25F);
            this.bunifuLabel2.ForeColor = System.Drawing.Color.White;
            this.bunifuLabel2.Location = new System.Drawing.Point(115, 20);
            this.bunifuLabel2.Name = "bunifuLabel2";
            this.bunifuLabel2.RightToLeft = System.Windows.Forms.RightToLeft.No;
            this.bunifuLabel2.Size = new System.Drawing.Size(49, 37);
            this.bunifuLabel2.TabIndex = 4;
            this.bunifuLabel2.Text = "Text";
            this.bunifuLabel2.TextAlignment = System.Drawing.ContentAlignment.TopLeft;
            this.bunifuLabel2.TextFormat = Bunifu.UI.WinForms.BunifuLabel.TextFormattingOptions.Default;
            // 
            // bunifuLabel1
            // 
            this.bunifuLabel1.AllowParentOverrides = false;
            this.bunifuLabel1.AutoEllipsis = false;
            this.bunifuLabel1.Cursor = System.Windows.Forms.Cursors.Default;
            this.bunifuLabel1.CursorType = System.Windows.Forms.Cursors.Default;
            this.bunifuLabel1.Font = new System.Drawing.Font("Segoe UI", 20.25F, System.Drawing.FontStyle.Bold);
            this.bunifuLabel1.ForeColor = System.Drawing.Color.White;
            this.bunifuLabel1.Location = new System.Drawing.Point(30, 20);
            this.bunifuLabel1.Name = "bunifuLabel1";
            this.bunifuLabel1.RightToLeft = System.Windows.Forms.RightToLeft.No;
            this.bunifuLabel1.Size = new System.Drawing.Size(85, 37);
            this.bunifuLabel1.TabIndex = 3;
            this.bunifuLabel1.Text = "Secure";
            this.bunifuLabel1.TextAlignment = System.Drawing.ContentAlignment.TopLeft;
            this.bunifuLabel1.TextFormat = Bunifu.UI.WinForms.BunifuLabel.TextFormattingOptions.Default;
            // 
            // cboProcedure
            // 
            this.cboProcedure.BackColor = System.Drawing.Color.Transparent;
            this.cboProcedure.BackgroundColor = System.Drawing.Color.FromArgb(((int)(((byte)(29)))), ((int)(((byte)(30)))), ((int)(((byte)(35)))));
            this.cboProcedure.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.cboProcedure.BorderRadius = 5;
            this.cboProcedure.Color = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.cboProcedure.Direction = Bunifu.UI.WinForms.BunifuDropdown.Directions.Down;
            this.cboProcedure.DisabledBackColor = System.Drawing.Color.FromArgb(((int)(((byte)(240)))), ((int)(((byte)(240)))), ((int)(((byte)(240)))));
            this.cboProcedure.DisabledBorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(204)))), ((int)(((byte)(204)))), ((int)(((byte)(204)))));
            this.cboProcedure.DisabledColor = System.Drawing.Color.FromArgb(((int)(((byte)(240)))), ((int)(((byte)(240)))), ((int)(((byte)(240)))));
            this.cboProcedure.DisabledForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(109)))), ((int)(((byte)(109)))), ((int)(((byte)(109)))));
            this.cboProcedure.DisabledIndicatorColor = System.Drawing.Color.DarkGray;
            this.cboProcedure.DrawMode = System.Windows.Forms.DrawMode.OwnerDrawFixed;
            this.cboProcedure.DropdownBorderThickness = Bunifu.UI.WinForms.BunifuDropdown.BorderThickness.Thick;
            this.cboProcedure.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cboProcedure.DropDownTextAlign = Bunifu.UI.WinForms.BunifuDropdown.TextAlign.Left;
            this.cboProcedure.FillDropDown = true;
            this.cboProcedure.FillIndicator = false;
            this.cboProcedure.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.cboProcedure.Font = new System.Drawing.Font("Segoe UI", 12F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cboProcedure.ForeColor = System.Drawing.Color.White;
            this.cboProcedure.FormattingEnabled = true;
            this.cboProcedure.Icon = null;
            this.cboProcedure.IndicatorAlignment = Bunifu.UI.WinForms.BunifuDropdown.Indicator.Right;
            this.cboProcedure.IndicatorColor = System.Drawing.Color.White;
            this.cboProcedure.IndicatorLocation = Bunifu.UI.WinForms.BunifuDropdown.Indicator.Right;
            this.cboProcedure.IndicatorThickness = 2;
            this.cboProcedure.IsDropdownOpened = false;
            this.cboProcedure.ItemBackColor = System.Drawing.Color.FromArgb(((int)(((byte)(29)))), ((int)(((byte)(30)))), ((int)(((byte)(35)))));
            this.cboProcedure.ItemBorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(29)))), ((int)(((byte)(30)))), ((int)(((byte)(35)))));
            this.cboProcedure.ItemForeColor = System.Drawing.Color.White;
            this.cboProcedure.ItemHeight = 31;
            this.cboProcedure.ItemHighLightColor = System.Drawing.Color.DodgerBlue;
            this.cboProcedure.ItemHighLightForeColor = System.Drawing.Color.White;
            this.cboProcedure.Items.AddRange(new object[] {
            "AES-256",
            "Triple DES",
            "Extended Triple DES",
            "Triple DES (2 rounds)",
            "Triple DES (4 rounds)",
            "RC4",
            "ROT13",
            "Base64"});
            this.cboProcedure.ItemTopMargin = 3;
            this.cboProcedure.Location = new System.Drawing.Point(30, 110);
            this.cboProcedure.Name = "cboProcedure";
            this.cboProcedure.Size = new System.Drawing.Size(320, 37);
            this.cboProcedure.TabIndex = 8;
            this.cboProcedure.Text = null;
            this.cboProcedure.TextAlignment = Bunifu.UI.WinForms.BunifuDropdown.TextAlign.Left;
            this.cboProcedure.TextLeftMargin = 5;
            this.cboProcedure.SelectedIndexChanged += new System.EventHandler(this.cboProcedure_SelectedIndexChanged);
            // 
            // bunifuLabel5
            // 
            this.bunifuLabel5.AllowParentOverrides = false;
            this.bunifuLabel5.AutoEllipsis = false;
            this.bunifuLabel5.CursorType = null;
            this.bunifuLabel5.Font = new System.Drawing.Font("Segoe UI", 14.25F, System.Drawing.FontStyle.Bold);
            this.bunifuLabel5.ForeColor = System.Drawing.Color.White;
            this.bunifuLabel5.Location = new System.Drawing.Point(30, 80);
            this.bunifuLabel5.Name = "bunifuLabel5";
            this.bunifuLabel5.RightToLeft = System.Windows.Forms.RightToLeft.No;
            this.bunifuLabel5.Size = new System.Drawing.Size(90, 25);
            this.bunifuLabel5.TabIndex = 7;
            this.bunifuLabel5.Text = "Algorithm";
            this.bunifuLabel5.TextAlignment = System.Drawing.ContentAlignment.TopLeft;
            this.bunifuLabel5.TextFormat = Bunifu.UI.WinForms.BunifuLabel.TextFormattingOptions.Default;
            // 
            // bunifuLabel4
            // 
            this.bunifuLabel4.AllowParentOverrides = false;
            this.bunifuLabel4.AutoEllipsis = false;
            this.bunifuLabel4.Cursor = System.Windows.Forms.Cursors.Default;
            this.bunifuLabel4.CursorType = System.Windows.Forms.Cursors.Default;
            this.bunifuLabel4.Font = new System.Drawing.Font("Segoe UI", 14.25F, System.Drawing.FontStyle.Bold);
            this.bunifuLabel4.ForeColor = System.Drawing.Color.White;
            this.bunifuLabel4.Location = new System.Drawing.Point(384, 80);
            this.bunifuLabel4.Name = "bunifuLabel4";
            this.bunifuLabel4.RightToLeft = System.Windows.Forms.RightToLeft.No;
            this.bunifuLabel4.Size = new System.Drawing.Size(85, 25);
            this.bunifuLabel4.TabIndex = 12;
            this.bunifuLabel4.Text = "Password";
            this.bunifuLabel4.TextAlignment = System.Drawing.ContentAlignment.TopLeft;
            this.bunifuLabel4.TextFormat = Bunifu.UI.WinForms.BunifuLabel.TextFormattingOptions.Default;
            // 
            // bunifuLabel6
            // 
            this.bunifuLabel6.AllowParentOverrides = false;
            this.bunifuLabel6.AutoEllipsis = false;
            this.bunifuLabel6.CursorType = null;
            this.bunifuLabel6.Font = new System.Drawing.Font("Segoe UI", 14.25F, System.Drawing.FontStyle.Bold);
            this.bunifuLabel6.ForeColor = System.Drawing.Color.White;
            this.bunifuLabel6.Location = new System.Drawing.Point(30, 170);
            this.bunifuLabel6.Name = "bunifuLabel6";
            this.bunifuLabel6.RightToLeft = System.Windows.Forms.RightToLeft.No;
            this.bunifuLabel6.Size = new System.Drawing.Size(83, 25);
            this.bunifuLabel6.TabIndex = 15;
            this.bunifuLabel6.Text = "Text data";
            this.bunifuLabel6.TextAlignment = System.Drawing.ContentAlignment.TopLeft;
            this.bunifuLabel6.TextFormat = Bunifu.UI.WinForms.BunifuLabel.TextFormattingOptions.Default;
            // 
            // Elipse
            // 
            this.Elipse.ElipseRadius = 20;
            this.Elipse.TargetControl = this;
            // 
            // btnClose
            // 
            this.btnClose.ActiveImage = null;
            this.btnClose.AllowAnimations = true;
            this.btnClose.AllowBuffering = false;
            this.btnClose.AllowToggling = false;
            this.btnClose.AllowZooming = true;
            this.btnClose.AllowZoomingOnFocus = false;
            this.btnClose.BackColor = System.Drawing.Color.Transparent;
            this.btnClose.DialogResult = System.Windows.Forms.DialogResult.None;
            this.btnClose.ErrorImage = ((System.Drawing.Image)(resources.GetObject("btnClose.ErrorImage")));
            this.btnClose.FadeWhenInactive = false;
            this.btnClose.Flip = Bunifu.UI.WinForms.BunifuImageButton.FlipOrientation.Normal;
            this.btnClose.Image = global::SecureText.Properties.Resources.Close;
            this.btnClose.ImageActive = null;
            this.btnClose.ImageLocation = null;
            this.btnClose.ImageMargin = 5;
            this.btnClose.ImageSize = new System.Drawing.Size(20, 20);
            this.btnClose.ImageZoomSize = new System.Drawing.Size(25, 25);
            this.btnClose.InitialImage = ((System.Drawing.Image)(resources.GetObject("btnClose.InitialImage")));
            this.btnClose.Location = new System.Drawing.Point(760, 12);
            this.btnClose.Name = "btnClose";
            this.btnClose.Rotation = 0;
            this.btnClose.ShowActiveImage = true;
            this.btnClose.ShowCursorChanges = true;
            this.btnClose.ShowImageBorders = true;
            this.btnClose.ShowSizeMarkers = false;
            this.btnClose.Size = new System.Drawing.Size(25, 25);
            this.btnClose.TabIndex = 29;
            this.btnClose.ToolTipText = "";
            this.btnClose.WaitOnLoad = false;
            this.btnClose.Zoom = 5;
            this.btnClose.ZoomSpeed = 10;
            this.btnClose.Click += new System.EventHandler(this.btnClose_Click);
            // 
            // btnDecrypt
            // 
            this.btnDecrypt.AllowAnimations = true;
            this.btnDecrypt.AllowMouseEffects = true;
            this.btnDecrypt.AllowToggling = false;
            this.btnDecrypt.AnimationSpeed = 200;
            this.btnDecrypt.AutoGenerateColors = false;
            this.btnDecrypt.AutoRoundBorders = false;
            this.btnDecrypt.AutoSizeLeftIcon = true;
            this.btnDecrypt.AutoSizeRightIcon = true;
            this.btnDecrypt.BackColor = System.Drawing.Color.Transparent;
            this.btnDecrypt.BackColor1 = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.btnDecrypt.BackgroundImage = ((System.Drawing.Image)(resources.GetObject("btnDecrypt.BackgroundImage")));
            this.btnDecrypt.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnDecrypt.ButtonText = "Decrypt";
            this.btnDecrypt.ButtonTextMarginLeft = 0;
            this.btnDecrypt.ColorContrastOnClick = 45;
            this.btnDecrypt.ColorContrastOnHover = 45;
            this.btnDecrypt.Cursor = System.Windows.Forms.Cursors.Default;
            borderEdges1.BottomLeft = true;
            borderEdges1.BottomRight = true;
            borderEdges1.TopLeft = true;
            borderEdges1.TopRight = true;
            this.btnDecrypt.CustomizableEdges = borderEdges1;
            this.btnDecrypt.DialogResult = System.Windows.Forms.DialogResult.None;
            this.btnDecrypt.DisabledBorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(41)))), ((int)(((byte)(43)))), ((int)(((byte)(56)))));
            this.btnDecrypt.DisabledFillColor = System.Drawing.Color.FromArgb(((int)(((byte)(191)))), ((int)(((byte)(191)))), ((int)(((byte)(191)))));
            this.btnDecrypt.DisabledForecolor = System.Drawing.Color.White;
            this.btnDecrypt.FocusState = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.ButtonStates.Pressed;
            this.btnDecrypt.Font = new System.Drawing.Font("Segoe UI", 15.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnDecrypt.ForeColor = System.Drawing.Color.White;
            this.btnDecrypt.IconLeftAlign = System.Drawing.ContentAlignment.MiddleLeft;
            this.btnDecrypt.IconLeftCursor = System.Windows.Forms.Cursors.Default;
            this.btnDecrypt.IconLeftPadding = new System.Windows.Forms.Padding(11, 3, 3, 3);
            this.btnDecrypt.IconMarginLeft = 11;
            this.btnDecrypt.IconPadding = 10;
            this.btnDecrypt.IconRightAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.btnDecrypt.IconRightCursor = System.Windows.Forms.Cursors.Default;
            this.btnDecrypt.IconRightPadding = new System.Windows.Forms.Padding(3, 3, 7, 3);
            this.btnDecrypt.IconSize = 25;
            this.btnDecrypt.IdleBorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(41)))), ((int)(((byte)(43)))), ((int)(((byte)(56)))));
            this.btnDecrypt.IdleBorderRadius = 10;
            this.btnDecrypt.IdleBorderThickness = 2;
            this.btnDecrypt.IdleFillColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.btnDecrypt.IdleIconLeftImage = null;
            this.btnDecrypt.IdleIconRightImage = null;
            this.btnDecrypt.IndicateFocus = false;
            this.btnDecrypt.Location = new System.Drawing.Point(212, 581);
            this.btnDecrypt.Name = "btnDecrypt";
            this.btnDecrypt.OnDisabledState.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(41)))), ((int)(((byte)(43)))), ((int)(((byte)(56)))));
            this.btnDecrypt.OnDisabledState.BorderRadius = 10;
            this.btnDecrypt.OnDisabledState.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnDecrypt.OnDisabledState.BorderThickness = 2;
            this.btnDecrypt.OnDisabledState.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(191)))), ((int)(((byte)(191)))), ((int)(((byte)(191)))));
            this.btnDecrypt.OnDisabledState.ForeColor = System.Drawing.Color.White;
            this.btnDecrypt.OnDisabledState.IconLeftImage = null;
            this.btnDecrypt.OnDisabledState.IconRightImage = null;
            this.btnDecrypt.onHoverState.BorderColor = System.Drawing.Color.White;
            this.btnDecrypt.onHoverState.BorderRadius = 10;
            this.btnDecrypt.onHoverState.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnDecrypt.onHoverState.BorderThickness = 2;
            this.btnDecrypt.onHoverState.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(122)))), ((int)(((byte)(182)))), ((int)(((byte)(246)))));
            this.btnDecrypt.onHoverState.ForeColor = System.Drawing.Color.White;
            this.btnDecrypt.onHoverState.IconLeftImage = null;
            this.btnDecrypt.onHoverState.IconRightImage = null;
            this.btnDecrypt.OnIdleState.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(41)))), ((int)(((byte)(43)))), ((int)(((byte)(56)))));
            this.btnDecrypt.OnIdleState.BorderRadius = 10;
            this.btnDecrypt.OnIdleState.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnDecrypt.OnIdleState.BorderThickness = 2;
            this.btnDecrypt.OnIdleState.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.btnDecrypt.OnIdleState.ForeColor = System.Drawing.Color.White;
            this.btnDecrypt.OnIdleState.IconLeftImage = null;
            this.btnDecrypt.OnIdleState.IconRightImage = null;
            this.btnDecrypt.OnPressedState.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(41)))), ((int)(((byte)(43)))), ((int)(((byte)(56)))));
            this.btnDecrypt.OnPressedState.BorderRadius = 10;
            this.btnDecrypt.OnPressedState.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnDecrypt.OnPressedState.BorderThickness = 2;
            this.btnDecrypt.OnPressedState.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.btnDecrypt.OnPressedState.ForeColor = System.Drawing.Color.White;
            this.btnDecrypt.OnPressedState.IconLeftImage = null;
            this.btnDecrypt.OnPressedState.IconRightImage = null;
            this.btnDecrypt.Size = new System.Drawing.Size(170, 45);
            this.btnDecrypt.TabIndex = 27;
            this.btnDecrypt.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.btnDecrypt.TextAlignment = System.Windows.Forms.HorizontalAlignment.Center;
            this.btnDecrypt.TextMarginLeft = 0;
            this.btnDecrypt.TextPadding = new System.Windows.Forms.Padding(0);
            this.btnDecrypt.UseDefaultRadiusAndThickness = true;
            this.btnDecrypt.Click += new System.EventHandler(this.btnDecrypt_Click);
            // 
            // btnCopy
            // 
            this.btnCopy.AllowAnimations = true;
            this.btnCopy.AllowMouseEffects = true;
            this.btnCopy.AllowToggling = false;
            this.btnCopy.AnimationSpeed = 200;
            this.btnCopy.AutoGenerateColors = false;
            this.btnCopy.AutoRoundBorders = false;
            this.btnCopy.AutoSizeLeftIcon = true;
            this.btnCopy.AutoSizeRightIcon = true;
            this.btnCopy.BackColor = System.Drawing.Color.Transparent;
            this.btnCopy.BackColor1 = System.Drawing.Color.FromArgb(((int)(((byte)(29)))), ((int)(((byte)(30)))), ((int)(((byte)(35)))));
            this.btnCopy.BackgroundImage = ((System.Drawing.Image)(resources.GetObject("btnCopy.BackgroundImage")));
            this.btnCopy.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnCopy.ButtonText = "Copy";
            this.btnCopy.ButtonTextMarginLeft = 0;
            this.btnCopy.ColorContrastOnClick = 45;
            this.btnCopy.ColorContrastOnHover = 45;
            this.btnCopy.Cursor = System.Windows.Forms.Cursors.Default;
            borderEdges2.BottomLeft = true;
            borderEdges2.BottomRight = true;
            borderEdges2.TopLeft = true;
            borderEdges2.TopRight = true;
            this.btnCopy.CustomizableEdges = borderEdges2;
            this.btnCopy.DialogResult = System.Windows.Forms.DialogResult.None;
            this.btnCopy.DisabledBorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(41)))), ((int)(((byte)(43)))), ((int)(((byte)(56)))));
            this.btnCopy.DisabledFillColor = System.Drawing.Color.FromArgb(((int)(((byte)(191)))), ((int)(((byte)(191)))), ((int)(((byte)(191)))));
            this.btnCopy.DisabledForecolor = System.Drawing.Color.White;
            this.btnCopy.FocusState = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.ButtonStates.Pressed;
            this.btnCopy.Font = new System.Drawing.Font("Segoe UI", 15.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnCopy.ForeColor = System.Drawing.Color.White;
            this.btnCopy.IconLeftAlign = System.Drawing.ContentAlignment.MiddleLeft;
            this.btnCopy.IconLeftCursor = System.Windows.Forms.Cursors.Default;
            this.btnCopy.IconLeftPadding = new System.Windows.Forms.Padding(11, 3, 3, 3);
            this.btnCopy.IconMarginLeft = 11;
            this.btnCopy.IconPadding = 10;
            this.btnCopy.IconRightAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.btnCopy.IconRightCursor = System.Windows.Forms.Cursors.Default;
            this.btnCopy.IconRightPadding = new System.Windows.Forms.Padding(3, 3, 7, 3);
            this.btnCopy.IconSize = 25;
            this.btnCopy.IdleBorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.btnCopy.IdleBorderRadius = 10;
            this.btnCopy.IdleBorderThickness = 2;
            this.btnCopy.IdleFillColor = System.Drawing.Color.FromArgb(((int)(((byte)(29)))), ((int)(((byte)(30)))), ((int)(((byte)(35)))));
            this.btnCopy.IdleIconLeftImage = null;
            this.btnCopy.IdleIconRightImage = null;
            this.btnCopy.IndicateFocus = false;
            this.btnCopy.Location = new System.Drawing.Point(394, 581);
            this.btnCopy.Name = "btnCopy";
            this.btnCopy.OnDisabledState.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(41)))), ((int)(((byte)(43)))), ((int)(((byte)(56)))));
            this.btnCopy.OnDisabledState.BorderRadius = 10;
            this.btnCopy.OnDisabledState.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnCopy.OnDisabledState.BorderThickness = 2;
            this.btnCopy.OnDisabledState.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(191)))), ((int)(((byte)(191)))), ((int)(((byte)(191)))));
            this.btnCopy.OnDisabledState.ForeColor = System.Drawing.Color.White;
            this.btnCopy.OnDisabledState.IconLeftImage = null;
            this.btnCopy.OnDisabledState.IconRightImage = null;
            this.btnCopy.onHoverState.BorderColor = System.Drawing.Color.White;
            this.btnCopy.onHoverState.BorderRadius = 10;
            this.btnCopy.onHoverState.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnCopy.onHoverState.BorderThickness = 2;
            this.btnCopy.onHoverState.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(56)))), ((int)(((byte)(57)))), ((int)(((byte)(65)))));
            this.btnCopy.onHoverState.ForeColor = System.Drawing.Color.White;
            this.btnCopy.onHoverState.IconLeftImage = null;
            this.btnCopy.onHoverState.IconRightImage = null;
            this.btnCopy.OnIdleState.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.btnCopy.OnIdleState.BorderRadius = 10;
            this.btnCopy.OnIdleState.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnCopy.OnIdleState.BorderThickness = 2;
            this.btnCopy.OnIdleState.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(29)))), ((int)(((byte)(30)))), ((int)(((byte)(35)))));
            this.btnCopy.OnIdleState.ForeColor = System.Drawing.Color.White;
            this.btnCopy.OnIdleState.IconLeftImage = null;
            this.btnCopy.OnIdleState.IconRightImage = null;
            this.btnCopy.OnPressedState.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(41)))), ((int)(((byte)(43)))), ((int)(((byte)(56)))));
            this.btnCopy.OnPressedState.BorderRadius = 10;
            this.btnCopy.OnPressedState.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnCopy.OnPressedState.BorderThickness = 2;
            this.btnCopy.OnPressedState.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(29)))), ((int)(((byte)(30)))), ((int)(((byte)(35)))));
            this.btnCopy.OnPressedState.ForeColor = System.Drawing.Color.White;
            this.btnCopy.OnPressedState.IconLeftImage = null;
            this.btnCopy.OnPressedState.IconRightImage = null;
            this.btnCopy.Size = new System.Drawing.Size(170, 45);
            this.btnCopy.TabIndex = 25;
            this.btnCopy.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.btnCopy.TextAlignment = System.Windows.Forms.HorizontalAlignment.Center;
            this.btnCopy.TextMarginLeft = 0;
            this.btnCopy.TextPadding = new System.Windows.Forms.Padding(0);
            this.btnCopy.UseDefaultRadiusAndThickness = true;
            this.btnCopy.Click += new System.EventHandler(this.btnCopy_Click);
            // 
            // btnEncrypt
            // 
            this.btnEncrypt.AllowAnimations = true;
            this.btnEncrypt.AllowMouseEffects = true;
            this.btnEncrypt.AllowToggling = false;
            this.btnEncrypt.AnimationSpeed = 200;
            this.btnEncrypt.AutoGenerateColors = false;
            this.btnEncrypt.AutoRoundBorders = false;
            this.btnEncrypt.AutoSizeLeftIcon = true;
            this.btnEncrypt.AutoSizeRightIcon = true;
            this.btnEncrypt.BackColor = System.Drawing.Color.Transparent;
            this.btnEncrypt.BackColor1 = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.btnEncrypt.BackgroundImage = ((System.Drawing.Image)(resources.GetObject("btnEncrypt.BackgroundImage")));
            this.btnEncrypt.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnEncrypt.ButtonText = "Encrypt";
            this.btnEncrypt.ButtonTextMarginLeft = 0;
            this.btnEncrypt.ColorContrastOnClick = 45;
            this.btnEncrypt.ColorContrastOnHover = 45;
            this.btnEncrypt.Cursor = System.Windows.Forms.Cursors.Default;
            borderEdges3.BottomLeft = true;
            borderEdges3.BottomRight = true;
            borderEdges3.TopLeft = true;
            borderEdges3.TopRight = true;
            this.btnEncrypt.CustomizableEdges = borderEdges3;
            this.btnEncrypt.DialogResult = System.Windows.Forms.DialogResult.None;
            this.btnEncrypt.DisabledBorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(41)))), ((int)(((byte)(43)))), ((int)(((byte)(56)))));
            this.btnEncrypt.DisabledFillColor = System.Drawing.Color.FromArgb(((int)(((byte)(191)))), ((int)(((byte)(191)))), ((int)(((byte)(191)))));
            this.btnEncrypt.DisabledForecolor = System.Drawing.Color.White;
            this.btnEncrypt.FocusState = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.ButtonStates.Pressed;
            this.btnEncrypt.Font = new System.Drawing.Font("Segoe UI", 15.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnEncrypt.ForeColor = System.Drawing.Color.White;
            this.btnEncrypt.IconLeftAlign = System.Drawing.ContentAlignment.MiddleLeft;
            this.btnEncrypt.IconLeftCursor = System.Windows.Forms.Cursors.Default;
            this.btnEncrypt.IconLeftPadding = new System.Windows.Forms.Padding(11, 3, 3, 3);
            this.btnEncrypt.IconMarginLeft = 11;
            this.btnEncrypt.IconPadding = 10;
            this.btnEncrypt.IconRightAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.btnEncrypt.IconRightCursor = System.Windows.Forms.Cursors.Default;
            this.btnEncrypt.IconRightPadding = new System.Windows.Forms.Padding(3, 3, 7, 3);
            this.btnEncrypt.IconSize = 25;
            this.btnEncrypt.IdleBorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(41)))), ((int)(((byte)(43)))), ((int)(((byte)(56)))));
            this.btnEncrypt.IdleBorderRadius = 10;
            this.btnEncrypt.IdleBorderThickness = 2;
            this.btnEncrypt.IdleFillColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.btnEncrypt.IdleIconLeftImage = null;
            this.btnEncrypt.IdleIconRightImage = null;
            this.btnEncrypt.IndicateFocus = false;
            this.btnEncrypt.Location = new System.Drawing.Point(30, 581);
            this.btnEncrypt.Name = "btnEncrypt";
            this.btnEncrypt.OnDisabledState.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(41)))), ((int)(((byte)(43)))), ((int)(((byte)(56)))));
            this.btnEncrypt.OnDisabledState.BorderRadius = 10;
            this.btnEncrypt.OnDisabledState.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnEncrypt.OnDisabledState.BorderThickness = 2;
            this.btnEncrypt.OnDisabledState.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(191)))), ((int)(((byte)(191)))), ((int)(((byte)(191)))));
            this.btnEncrypt.OnDisabledState.ForeColor = System.Drawing.Color.White;
            this.btnEncrypt.OnDisabledState.IconLeftImage = null;
            this.btnEncrypt.OnDisabledState.IconRightImage = null;
            this.btnEncrypt.onHoverState.BorderColor = System.Drawing.Color.White;
            this.btnEncrypt.onHoverState.BorderRadius = 10;
            this.btnEncrypt.onHoverState.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnEncrypt.onHoverState.BorderThickness = 2;
            this.btnEncrypt.onHoverState.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(122)))), ((int)(((byte)(182)))), ((int)(((byte)(246)))));
            this.btnEncrypt.onHoverState.ForeColor = System.Drawing.Color.White;
            this.btnEncrypt.onHoverState.IconLeftImage = null;
            this.btnEncrypt.onHoverState.IconRightImage = null;
            this.btnEncrypt.OnIdleState.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(41)))), ((int)(((byte)(43)))), ((int)(((byte)(56)))));
            this.btnEncrypt.OnIdleState.BorderRadius = 10;
            this.btnEncrypt.OnIdleState.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnEncrypt.OnIdleState.BorderThickness = 2;
            this.btnEncrypt.OnIdleState.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.btnEncrypt.OnIdleState.ForeColor = System.Drawing.Color.White;
            this.btnEncrypt.OnIdleState.IconLeftImage = null;
            this.btnEncrypt.OnIdleState.IconRightImage = null;
            this.btnEncrypt.OnPressedState.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(41)))), ((int)(((byte)(43)))), ((int)(((byte)(56)))));
            this.btnEncrypt.OnPressedState.BorderRadius = 10;
            this.btnEncrypt.OnPressedState.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnEncrypt.OnPressedState.BorderThickness = 2;
            this.btnEncrypt.OnPressedState.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.btnEncrypt.OnPressedState.ForeColor = System.Drawing.Color.White;
            this.btnEncrypt.OnPressedState.IconLeftImage = null;
            this.btnEncrypt.OnPressedState.IconRightImage = null;
            this.btnEncrypt.Size = new System.Drawing.Size(170, 45);
            this.btnEncrypt.TabIndex = 24;
            this.btnEncrypt.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.btnEncrypt.TextAlignment = System.Windows.Forms.HorizontalAlignment.Center;
            this.btnEncrypt.TextMarginLeft = 0;
            this.btnEncrypt.TextPadding = new System.Windows.Forms.Padding(0);
            this.btnEncrypt.UseDefaultRadiusAndThickness = true;
            this.btnEncrypt.Click += new System.EventHandler(this.btnEncrypt_Click);
            // 
            // btnGeneratePassword
            // 
            this.btnGeneratePassword.AllowAnimations = true;
            this.btnGeneratePassword.AllowMouseEffects = true;
            this.btnGeneratePassword.AllowToggling = false;
            this.btnGeneratePassword.AnimationSpeed = 200;
            this.btnGeneratePassword.AutoGenerateColors = false;
            this.btnGeneratePassword.AutoRoundBorders = false;
            this.btnGeneratePassword.AutoSizeLeftIcon = true;
            this.btnGeneratePassword.AutoSizeRightIcon = true;
            this.btnGeneratePassword.BackColor = System.Drawing.Color.Transparent;
            this.btnGeneratePassword.BackColor1 = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.btnGeneratePassword.BackgroundImage = ((System.Drawing.Image)(resources.GetObject("btnGeneratePassword.BackgroundImage")));
            this.btnGeneratePassword.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnGeneratePassword.ButtonText = "";
            this.btnGeneratePassword.ButtonTextMarginLeft = 0;
            this.btnGeneratePassword.ColorContrastOnClick = 45;
            this.btnGeneratePassword.ColorContrastOnHover = 45;
            this.btnGeneratePassword.Cursor = System.Windows.Forms.Cursors.Default;
            borderEdges4.BottomLeft = true;
            borderEdges4.BottomRight = true;
            borderEdges4.TopLeft = true;
            borderEdges4.TopRight = true;
            this.btnGeneratePassword.CustomizableEdges = borderEdges4;
            this.btnGeneratePassword.DialogResult = System.Windows.Forms.DialogResult.None;
            this.btnGeneratePassword.DisabledBorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(191)))), ((int)(((byte)(191)))), ((int)(((byte)(191)))));
            this.btnGeneratePassword.DisabledFillColor = System.Drawing.Color.FromArgb(((int)(((byte)(191)))), ((int)(((byte)(191)))), ((int)(((byte)(191)))));
            this.btnGeneratePassword.DisabledForecolor = System.Drawing.Color.FromArgb(((int)(((byte)(168)))), ((int)(((byte)(160)))), ((int)(((byte)(168)))));
            this.btnGeneratePassword.FocusState = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.ButtonStates.Pressed;
            this.btnGeneratePassword.Font = new System.Drawing.Font("Segoe UI", 9F);
            this.btnGeneratePassword.ForeColor = System.Drawing.Color.White;
            this.btnGeneratePassword.IconLeftAlign = System.Drawing.ContentAlignment.MiddleLeft;
            this.btnGeneratePassword.IconLeftCursor = System.Windows.Forms.Cursors.Default;
            this.btnGeneratePassword.IconLeftPadding = new System.Windows.Forms.Padding(8, 3, 3, 3);
            this.btnGeneratePassword.IconMarginLeft = 11;
            this.btnGeneratePassword.IconPadding = 5;
            this.btnGeneratePassword.IconRightAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.btnGeneratePassword.IconRightCursor = System.Windows.Forms.Cursors.Default;
            this.btnGeneratePassword.IconRightPadding = new System.Windows.Forms.Padding(3, 3, 7, 3);
            this.btnGeneratePassword.IconSize = 25;
            this.btnGeneratePassword.IdleBorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(41)))), ((int)(((byte)(43)))), ((int)(((byte)(56)))));
            this.btnGeneratePassword.IdleBorderRadius = 8;
            this.btnGeneratePassword.IdleBorderThickness = 2;
            this.btnGeneratePassword.IdleFillColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.btnGeneratePassword.IdleIconLeftImage = global::SecureText.Properties.Resources.Password;
            this.btnGeneratePassword.IdleIconRightImage = null;
            this.btnGeneratePassword.IndicateFocus = false;
            this.btnGeneratePassword.Location = new System.Drawing.Point(720, 108);
            this.btnGeneratePassword.Name = "btnGeneratePassword";
            this.btnGeneratePassword.OnDisabledState.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(191)))), ((int)(((byte)(191)))), ((int)(((byte)(191)))));
            this.btnGeneratePassword.OnDisabledState.BorderRadius = 8;
            this.btnGeneratePassword.OnDisabledState.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnGeneratePassword.OnDisabledState.BorderThickness = 2;
            this.btnGeneratePassword.OnDisabledState.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(191)))), ((int)(((byte)(191)))), ((int)(((byte)(191)))));
            this.btnGeneratePassword.OnDisabledState.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(168)))), ((int)(((byte)(160)))), ((int)(((byte)(168)))));
            this.btnGeneratePassword.OnDisabledState.IconLeftImage = null;
            this.btnGeneratePassword.OnDisabledState.IconRightImage = null;
            this.btnGeneratePassword.onHoverState.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(122)))), ((int)(((byte)(182)))), ((int)(((byte)(246)))));
            this.btnGeneratePassword.onHoverState.BorderRadius = 8;
            this.btnGeneratePassword.onHoverState.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnGeneratePassword.onHoverState.BorderThickness = 2;
            this.btnGeneratePassword.onHoverState.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(122)))), ((int)(((byte)(182)))), ((int)(((byte)(246)))));
            this.btnGeneratePassword.onHoverState.ForeColor = System.Drawing.Color.White;
            this.btnGeneratePassword.onHoverState.IconLeftImage = null;
            this.btnGeneratePassword.onHoverState.IconRightImage = null;
            this.btnGeneratePassword.OnIdleState.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(41)))), ((int)(((byte)(43)))), ((int)(((byte)(56)))));
            this.btnGeneratePassword.OnIdleState.BorderRadius = 8;
            this.btnGeneratePassword.OnIdleState.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnGeneratePassword.OnIdleState.BorderThickness = 2;
            this.btnGeneratePassword.OnIdleState.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.btnGeneratePassword.OnIdleState.ForeColor = System.Drawing.Color.White;
            this.btnGeneratePassword.OnIdleState.IconLeftImage = global::SecureText.Properties.Resources.Password;
            this.btnGeneratePassword.OnIdleState.IconRightImage = null;
            this.btnGeneratePassword.OnPressedState.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(41)))), ((int)(((byte)(43)))), ((int)(((byte)(56)))));
            this.btnGeneratePassword.OnPressedState.BorderRadius = 8;
            this.btnGeneratePassword.OnPressedState.BorderStyle = Bunifu.UI.WinForms.BunifuButton.BunifuButton2.BorderStyles.Solid;
            this.btnGeneratePassword.OnPressedState.BorderThickness = 2;
            this.btnGeneratePassword.OnPressedState.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.btnGeneratePassword.OnPressedState.ForeColor = System.Drawing.Color.White;
            this.btnGeneratePassword.OnPressedState.IconLeftImage = null;
            this.btnGeneratePassword.OnPressedState.IconRightImage = null;
            this.btnGeneratePassword.Size = new System.Drawing.Size(50, 42);
            this.btnGeneratePassword.TabIndex = 14;
            this.btnGeneratePassword.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.btnGeneratePassword.TextAlignment = System.Windows.Forms.HorizontalAlignment.Center;
            this.btnGeneratePassword.TextMarginLeft = 0;
            this.btnGeneratePassword.TextPadding = new System.Windows.Forms.Padding(0);
            this.btnGeneratePassword.UseDefaultRadiusAndThickness = true;
            this.btnGeneratePassword.Click += new System.EventHandler(this.btnGeneratePassword_Click);
            // 
            // txtPassword
            // 
            this.txtPassword.AcceptsReturn = false;
            this.txtPassword.AcceptsTab = false;
            this.txtPassword.AnimationSpeed = 200;
            this.txtPassword.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.None;
            this.txtPassword.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.None;
            this.txtPassword.AutoSizeHeight = true;
            this.txtPassword.BackColor = System.Drawing.Color.Transparent;
            this.txtPassword.BackgroundImage = ((System.Drawing.Image)(resources.GetObject("txtPassword.BackgroundImage")));
            this.txtPassword.BorderColorActive = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.txtPassword.BorderColorDisabled = System.Drawing.Color.FromArgb(((int)(((byte)(204)))), ((int)(((byte)(204)))), ((int)(((byte)(204)))));
            this.txtPassword.BorderColorHover = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.txtPassword.BorderColorIdle = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.txtPassword.BorderRadius = 10;
            this.txtPassword.BorderThickness = 2;
            this.txtPassword.CharacterCasing = System.Windows.Forms.CharacterCasing.Normal;
            this.txtPassword.Cursor = System.Windows.Forms.Cursors.IBeam;
            this.txtPassword.DefaultFont = new System.Drawing.Font("Segoe UI", 12F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtPassword.DefaultText = "";
            this.txtPassword.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(29)))), ((int)(((byte)(30)))), ((int)(((byte)(35)))));
            this.txtPassword.ForeColor = System.Drawing.Color.White;
            this.txtPassword.HideSelection = true;
            this.txtPassword.IconLeft = null;
            this.txtPassword.IconLeftCursor = System.Windows.Forms.Cursors.IBeam;
            this.txtPassword.IconPadding = 10;
            this.txtPassword.IconRight = null;
            this.txtPassword.IconRightCursor = System.Windows.Forms.Cursors.IBeam;
            this.txtPassword.Lines = new string[0];
            this.txtPassword.Location = new System.Drawing.Point(384, 108);
            this.txtPassword.MaxLength = 32767;
            this.txtPassword.MinimumSize = new System.Drawing.Size(1, 1);
            this.txtPassword.Modified = false;
            this.txtPassword.Multiline = false;
            this.txtPassword.Name = "txtPassword";
            stateProperties1.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            stateProperties1.FillColor = System.Drawing.Color.Empty;
            stateProperties1.ForeColor = System.Drawing.Color.Empty;
            stateProperties1.PlaceholderForeColor = System.Drawing.Color.Empty;
            this.txtPassword.OnActiveState = stateProperties1;
            stateProperties2.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(204)))), ((int)(((byte)(204)))), ((int)(((byte)(204)))));
            stateProperties2.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(29)))), ((int)(((byte)(30)))), ((int)(((byte)(35)))));
            stateProperties2.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(109)))), ((int)(((byte)(109)))), ((int)(((byte)(109)))));
            stateProperties2.PlaceholderForeColor = System.Drawing.Color.DarkGray;
            this.txtPassword.OnDisabledState = stateProperties2;
            stateProperties3.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            stateProperties3.FillColor = System.Drawing.Color.Empty;
            stateProperties3.ForeColor = System.Drawing.Color.Empty;
            stateProperties3.PlaceholderForeColor = System.Drawing.Color.Empty;
            this.txtPassword.OnHoverState = stateProperties3;
            stateProperties4.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            stateProperties4.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(29)))), ((int)(((byte)(30)))), ((int)(((byte)(35)))));
            stateProperties4.ForeColor = System.Drawing.Color.White;
            stateProperties4.PlaceholderForeColor = System.Drawing.Color.Empty;
            this.txtPassword.OnIdleState = stateProperties4;
            this.txtPassword.Padding = new System.Windows.Forms.Padding(3);
            this.txtPassword.PasswordChar = '\0';
            this.txtPassword.PlaceholderForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(200)))), ((int)(((byte)(200)))), ((int)(((byte)(200)))));
            this.txtPassword.PlaceholderText = "";
            this.txtPassword.ReadOnly = false;
            this.txtPassword.ScrollBars = System.Windows.Forms.ScrollBars.None;
            this.txtPassword.SelectedText = "";
            this.txtPassword.SelectionLength = 0;
            this.txtPassword.SelectionStart = 0;
            this.txtPassword.ShortcutsEnabled = true;
            this.txtPassword.Size = new System.Drawing.Size(320, 40);
            this.txtPassword.Style = Bunifu.UI.WinForms.BunifuTextBox._Style.Bunifu;
            this.txtPassword.TabIndex = 13;
            this.txtPassword.TextAlign = System.Windows.Forms.HorizontalAlignment.Left;
            this.txtPassword.TextMarginBottom = 0;
            this.txtPassword.TextMarginLeft = 3;
            this.txtPassword.TextMarginTop = 1;
            this.txtPassword.TextPlaceholder = "";
            this.txtPassword.UseSystemPasswordChar = false;
            this.txtPassword.WordWrap = true;
            this.txtPassword.MouseDoubleClick += new System.Windows.Forms.MouseEventHandler(this.txtPassword_MouseDoubleClick);
            this.txtPassword.MouseLeave += new System.EventHandler(this.txtPassword_MouseLeave);
            this.txtPassword.MouseHover += new System.EventHandler(this.txtPassword_MouseHover);
            // 
            // bgwEncrypt
            // 
            this.bgwEncrypt.DoWork += new System.ComponentModel.DoWorkEventHandler(this.bgwEncrypt_DoWork);
            this.bgwEncrypt.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(this.bgwEncrypt_RunWorkerCompleted);
            // 
            // bgwDecrypt
            // 
            this.bgwDecrypt.DoWork += new System.ComponentModel.DoWorkEventHandler(this.bgwDecrypt_DoWork);
            this.bgwDecrypt.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(this.bgwDecrypt_RunWorkerCompleted);
            // 
            // DragControl
            // 
            this.DragControl.Fixed = true;
            this.DragControl.Horizontal = true;
            this.DragControl.TargetControl = this;
            this.DragControl.Vertical = true;
            // 
            // sbMessage
            // 
            this.sbMessage.AllowDragging = false;
            this.sbMessage.AllowMultipleViews = true;
            this.sbMessage.ClickToClose = true;
            this.sbMessage.DoubleClickToClose = true;
            this.sbMessage.DurationAfterIdle = 3000;
            this.sbMessage.ErrorOptions.ActionBackColor = System.Drawing.Color.FromArgb(((int)(((byte)(255)))), ((int)(((byte)(255)))), ((int)(((byte)(255)))));
            this.sbMessage.ErrorOptions.ActionBorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(255)))), ((int)(((byte)(255)))), ((int)(((byte)(255)))));
            this.sbMessage.ErrorOptions.ActionBorderRadius = 1;
            this.sbMessage.ErrorOptions.ActionFont = new System.Drawing.Font("Segoe UI", 8.25F, System.Drawing.FontStyle.Bold);
            this.sbMessage.ErrorOptions.ActionForeColor = System.Drawing.Color.Black;
            this.sbMessage.ErrorOptions.BackColor = System.Drawing.Color.White;
            this.sbMessage.ErrorOptions.BorderColor = System.Drawing.Color.White;
            this.sbMessage.ErrorOptions.CloseIconColor = System.Drawing.Color.FromArgb(((int)(((byte)(255)))), ((int)(((byte)(204)))), ((int)(((byte)(199)))));
            this.sbMessage.ErrorOptions.Font = new System.Drawing.Font("Segoe UI", 9.75F);
            this.sbMessage.ErrorOptions.ForeColor = System.Drawing.Color.Black;
            this.sbMessage.ErrorOptions.Icon = ((System.Drawing.Image)(resources.GetObject("resource.Icon")));
            this.sbMessage.ErrorOptions.IconLeftMargin = 12;
            this.sbMessage.FadeCloseIcon = false;
            this.sbMessage.Host = Bunifu.UI.WinForms.BunifuSnackbar.Hosts.FormOwner;
            this.sbMessage.InformationOptions.ActionBackColor = System.Drawing.Color.FromArgb(((int)(((byte)(255)))), ((int)(((byte)(255)))), ((int)(((byte)(255)))));
            this.sbMessage.InformationOptions.ActionBorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(255)))), ((int)(((byte)(255)))), ((int)(((byte)(255)))));
            this.sbMessage.InformationOptions.ActionBorderRadius = 1;
            this.sbMessage.InformationOptions.ActionFont = new System.Drawing.Font("Segoe UI", 8.25F, System.Drawing.FontStyle.Bold);
            this.sbMessage.InformationOptions.ActionForeColor = System.Drawing.Color.Black;
            this.sbMessage.InformationOptions.BackColor = System.Drawing.Color.White;
            this.sbMessage.InformationOptions.BorderColor = System.Drawing.Color.White;
            this.sbMessage.InformationOptions.CloseIconColor = System.Drawing.Color.FromArgb(((int)(((byte)(145)))), ((int)(((byte)(213)))), ((int)(((byte)(255)))));
            this.sbMessage.InformationOptions.Font = new System.Drawing.Font("Segoe UI", 9.75F);
            this.sbMessage.InformationOptions.ForeColor = System.Drawing.Color.Black;
            this.sbMessage.InformationOptions.Icon = ((System.Drawing.Image)(resources.GetObject("resource.Icon1")));
            this.sbMessage.InformationOptions.IconLeftMargin = 12;
            this.sbMessage.Margin = 10;
            this.sbMessage.MaximumSize = new System.Drawing.Size(0, 0);
            this.sbMessage.MaximumViews = 7;
            this.sbMessage.MessageRightMargin = 15;
            this.sbMessage.MinimumSize = new System.Drawing.Size(0, 0);
            this.sbMessage.ShowBorders = false;
            this.sbMessage.ShowCloseIcon = true;
            this.sbMessage.ShowIcon = true;
            this.sbMessage.ShowShadows = true;
            this.sbMessage.SuccessOptions.ActionBackColor = System.Drawing.Color.FromArgb(((int)(((byte)(255)))), ((int)(((byte)(255)))), ((int)(((byte)(255)))));
            this.sbMessage.SuccessOptions.ActionBorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(255)))), ((int)(((byte)(255)))), ((int)(((byte)(255)))));
            this.sbMessage.SuccessOptions.ActionBorderRadius = 1;
            this.sbMessage.SuccessOptions.ActionFont = new System.Drawing.Font("Segoe UI", 12F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.sbMessage.SuccessOptions.ActionForeColor = System.Drawing.Color.Black;
            this.sbMessage.SuccessOptions.BackColor = System.Drawing.Color.White;
            this.sbMessage.SuccessOptions.BorderColor = System.Drawing.Color.White;
            this.sbMessage.SuccessOptions.CloseIconColor = System.Drawing.Color.Black;
            this.sbMessage.SuccessOptions.Font = new System.Drawing.Font("Segoe UI", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.sbMessage.SuccessOptions.ForeColor = System.Drawing.Color.Black;
            this.sbMessage.SuccessOptions.Icon = ((System.Drawing.Image)(resources.GetObject("resource.Icon2")));
            this.sbMessage.SuccessOptions.IconLeftMargin = 12;
            this.sbMessage.ViewsMargin = 7;
            this.sbMessage.WarningOptions.ActionBackColor = System.Drawing.Color.FromArgb(((int)(((byte)(255)))), ((int)(((byte)(255)))), ((int)(((byte)(255)))));
            this.sbMessage.WarningOptions.ActionBorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(255)))), ((int)(((byte)(255)))), ((int)(((byte)(255)))));
            this.sbMessage.WarningOptions.ActionBorderRadius = 1;
            this.sbMessage.WarningOptions.ActionFont = new System.Drawing.Font("Segoe UI", 12F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.sbMessage.WarningOptions.ActionForeColor = System.Drawing.Color.Black;
            this.sbMessage.WarningOptions.BackColor = System.Drawing.Color.White;
            this.sbMessage.WarningOptions.BorderColor = System.Drawing.Color.White;
            this.sbMessage.WarningOptions.CloseIconColor = System.Drawing.Color.Black;
            this.sbMessage.WarningOptions.Font = new System.Drawing.Font("Segoe UI", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.sbMessage.WarningOptions.ForeColor = System.Drawing.Color.Black;
            this.sbMessage.WarningOptions.Icon = ((System.Drawing.Image)(resources.GetObject("resource.Icon3")));
            this.sbMessage.WarningOptions.IconLeftMargin = 12;
            this.sbMessage.ZoomCloseIcon = true;
            // 
            // txtText
            // 
            this.txtText.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(29)))), ((int)(((byte)(30)))), ((int)(((byte)(35)))));
            this.txtText.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.txtText.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtText.ForeColor = System.Drawing.Color.White;
            this.txtText.Location = new System.Drawing.Point(38, 208);
            this.txtText.Name = "txtText";
            this.txtText.ScrollBars = System.Windows.Forms.RichTextBoxScrollBars.Vertical;
            this.txtText.Size = new System.Drawing.Size(725, 360);
            this.txtText.TabIndex = 32;
            this.txtText.Text = "";
            this.txtText.TextChanged += new System.EventHandler(this.txtText_TextChanged);
            this.txtText.MouseDoubleClick += new System.Windows.Forms.MouseEventHandler(this.txtText_MouseDoubleClick);
            // 
            // UserControl
            // 
            this.UserControl.AllowAnimations = false;
            this.UserControl.AllowBorderColorChanges = false;
            this.UserControl.AllowMouseEffects = false;
            this.UserControl.AnimationSpeed = 200;
            this.UserControl.BackColor = System.Drawing.Color.Transparent;
            this.UserControl.BackgroundColor = System.Drawing.Color.Transparent;
            this.UserControl.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(161)))), ((int)(((byte)(250)))));
            this.UserControl.BorderRadius = 15;
            this.UserControl.BorderStyle = Bunifu.UI.WinForms.BunifuUserControl.BorderStyles.Solid;
            this.UserControl.BorderThickness = 2;
            this.UserControl.ColorContrastOnClick = 30;
            this.UserControl.ColorContrastOnHover = 30;
            this.UserControl.Cursor = System.Windows.Forms.Cursors.Default;
            this.UserControl.Image = null;
            this.UserControl.ImageMargin = new System.Windows.Forms.Padding(0);
            this.UserControl.Location = new System.Drawing.Point(30, 200);
            this.UserControl.Name = "UserControl";
            this.UserControl.ShowBorders = true;
            this.UserControl.Size = new System.Drawing.Size(740, 374);
            this.UserControl.Style = Bunifu.UI.WinForms.BunifuUserControl.UserControlStyles.Flat;
            this.UserControl.TabIndex = 33;
            // 
            // SecureText
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(41)))), ((int)(((byte)(43)))), ((int)(((byte)(56)))));
            this.ClientSize = new System.Drawing.Size(800, 650);
            this.Controls.Add(this.txtText);
            this.Controls.Add(this.btnClose);
            this.Controls.Add(this.btnDecrypt);
            this.Controls.Add(this.btnCopy);
            this.Controls.Add(this.btnEncrypt);
            this.Controls.Add(this.bunifuLabel6);
            this.Controls.Add(this.btnGeneratePassword);
            this.Controls.Add(this.txtPassword);
            this.Controls.Add(this.bunifuLabel4);
            this.Controls.Add(this.cboProcedure);
            this.Controls.Add(this.bunifuLabel5);
            this.Controls.Add(this.bunifuLabel3);
            this.Controls.Add(this.bunifuLabel2);
            this.Controls.Add(this.bunifuLabel1);
            this.Controls.Add(this.UserControl);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.Name = "SecureText";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "SecureText";
            this.Load += new System.EventHandler(this.SecureText_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private Bunifu.UI.WinForms.BunifuLabel bunifuLabel3;
        private Bunifu.UI.WinForms.BunifuLabel bunifuLabel2;
        private Bunifu.UI.WinForms.BunifuLabel bunifuLabel1;
        private Bunifu.UI.WinForms.BunifuDropdown cboProcedure;
        private Bunifu.UI.WinForms.BunifuLabel bunifuLabel5;
        private Bunifu.UI.WinForms.BunifuButton.BunifuButton2 btnGeneratePassword;
        private Bunifu.UI.WinForms.BunifuTextBox txtPassword;
        private Bunifu.UI.WinForms.BunifuLabel bunifuLabel4;
        private Bunifu.UI.WinForms.BunifuLabel bunifuLabel6;
        private Bunifu.UI.WinForms.BunifuButton.BunifuButton2 btnCopy;
        private Bunifu.UI.WinForms.BunifuButton.BunifuButton2 btnEncrypt;
        private Bunifu.UI.WinForms.BunifuButton.BunifuButton2 btnDecrypt;
        private Bunifu.UI.WinForms.BunifuImageButton btnClose;
        private Bunifu.Framework.UI.BunifuElipse Elipse;
        private System.ComponentModel.BackgroundWorker bgwEncrypt;
        private System.ComponentModel.BackgroundWorker bgwDecrypt;
        private Bunifu.Framework.UI.BunifuDragControl DragControl;
        private Bunifu.UI.WinForms.BunifuSnackbar sbMessage;
        private System.Windows.Forms.RichTextBox txtText;
        private Bunifu.UI.WinForms.BunifuUserControl UserControl;
    }
}

