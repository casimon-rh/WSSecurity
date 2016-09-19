namespace Client
{
    partial class WindowsClient
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
            this.cmdGo = new System.Windows.Forms.Button();
            this.txtRet = new System.Windows.Forms.TextBox();
            this.SuspendLayout();
            // 
            // cmdGo
            // 
            this.cmdGo.Location = new System.Drawing.Point(27, 12);
            this.cmdGo.Name = "cmdGo";
            this.cmdGo.Size = new System.Drawing.Size(75, 23);
            this.cmdGo.TabIndex = 0;
            this.cmdGo.Text = "Call Service";
            this.cmdGo.UseVisualStyleBackColor = true;
            this.cmdGo.Click += new System.EventHandler(this.cmdGo_Click);
            // 
            // txtRet
            // 
            this.txtRet.Location = new System.Drawing.Point(27, 57);
            this.txtRet.Multiline = true;
            this.txtRet.Name = "txtRet";
            this.txtRet.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.txtRet.Size = new System.Drawing.Size(130, 57);
            this.txtRet.TabIndex = 1;
            // 
            // WindowsClient
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(214, 137);
            this.Controls.Add(this.txtRet);
            this.Controls.Add(this.cmdGo);
            this.Name = "WindowsClient";
            this.Text = "Windows Client";
            this.Load += new System.EventHandler(this.Form1_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button cmdGo;
        private System.Windows.Forms.TextBox txtRet;
    }
}

