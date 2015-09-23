using System;
using System.Configuration;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace NoCaptchaReCaptcha
{
    public class NoCaptchaValidator : BaseValidator
    {
        private static readonly DateTime EpochStart = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private bool evaluateIsValidExecuted;

        #region Properties

        public Guid SessionKey { get; private set; }
        public string SiteKey { get; private set; }
        public string SecretKey { get; private set; }
        public bool UseSecureToken { get; set; }
        public NoCaptchaSettings.NoCaptchaTheme Theme { get; set; }
        public NoCaptchaSettings.NoCaptchaType Type { get; set; }
        public NoCaptchaSettings.NoCaptchaSize Size { get; set; }
        public string ErrorCssClass { get; set; }

        private string SecureToken
        {
            get { return EncryptSecurityToken(GetSecurtiyTokenJson()); }
        }

        #endregion

        public NoCaptchaValidator()
            : this(ConfigurationManager.AppSettings["NoCaptchaReCaptcha.SiteKey"], ConfigurationManager.AppSettings["NoCaptchaReCaptcha.SecretKey"])
        { }
        public NoCaptchaValidator(string siteKey, string secretKey)
        {
            this.SiteKey = siteKey;
            this.SecretKey = secretKey;
            this.UseSecureToken = true; // Allows multiple domains for key
            this.SessionKey = Guid.NewGuid();
            this.Theme = NoCaptchaSettings.NoCaptchaTheme.Light;
            this.Type = NoCaptchaSettings.NoCaptchaType.Image;
            this.Size = NoCaptchaSettings.NoCaptchaSize.Normal;
        }

        #region Methods

        protected override bool ControlPropertiesValid()
        {
            return true;
        }
        protected override void OnPreRender(EventArgs e)
        {
            if (!Page.ClientScript.IsClientScriptIncludeRegistered("NoCaptcha"))
            {
                Page.ClientScript.RegisterClientScriptInclude("NoCaptcha", NoCaptchaSettings.RecaptchaApiScript);
            }

            base.OnPreRender(e);
        }
        public override void RenderControl(HtmlTextWriter writer)
        {
            writer.AddAttribute(HtmlTextWriterAttribute.Class, NoCaptchaSettings.RecaptchaCssClass);
            writer.AddAttribute("data-sitekey", this.SiteKey);
            
            if (this.UseSecureToken)
            {
                writer.AddAttribute("data-stoken", this.SecureToken);
            }

            writer.AddAttribute("data-theme", this.Theme.ToString().ToLower());
            writer.AddAttribute("data-type", this.Type.ToString().ToLower());
            writer.AddAttribute("data-size", this.Size.ToString().ToLower());

            writer.RenderBeginTag(HtmlTextWriterTag.Div);
            writer.RenderEndTag();

            // If there is a summary group for this validation group then don't add message
            if (Page.IsPostBack && !this.IsValid && this.Display != ValidatorDisplay.None)
            {
                writer.AddAttribute(HtmlTextWriterAttribute.Class, this.ErrorCssClass);
                writer.RenderBeginTag(HtmlTextWriterTag.Span);
                writer.WriteEncodedText(this.Text);
                writer.RenderEndTag();
            }
        }
        protected override bool EvaluateIsValid()
        {
            // This is getting called twice for some reason and fails validation second time so handling once only
            if (this.evaluateIsValidExecuted)
                return this.IsValid;

            var noCaptchaValidator = new NoCaptchaRequest(this.SiteKey, this.SecretKey);
            this.IsValid = noCaptchaValidator.ValidateResponse();
            this.evaluateIsValidExecuted = true;
            this.Text = noCaptchaValidator.ErrorMessage;

            // Set Error Message for Validation Summary
            if (!this.IsValid && this.Display == ValidatorDisplay.None)
            {
                this.ErrorMessage = noCaptchaValidator.ErrorMessage;
            }

            return this.IsValid;
        }

        #endregion

        #region Security Token

        private string EncryptSecurityToken(string token)
        {
            byte[] cryptKey = GetEncryptedSecretKey(SecretKey);
            byte[] cryptToken = AesEncrypt(token, cryptKey, cryptKey);

            return Convert.ToBase64String(cryptToken)
                .Replace("=", "")
                .Replace("+", "-")
                .Replace("/", "_");
        }
        private string GetSecurtiyTokenJson()
        {
            return string.Format("{{\"session_id\": \"{0}\",\"ts_ms\": {1}}}", this.SessionKey, this.ToUnixTime(DateTime.UtcNow));
        }
        private long ToUnixTime(DateTime date)
        {
            return Convert.ToInt64((date - EpochStart).TotalMilliseconds);
        }
        private byte[] GetEncryptedSecretKey(string secretKey)
        {
            byte[] baseKeyBytes = Encoding.UTF8.GetBytes(secretKey);
            byte[] baseKeySha1;
            using (SHA1 sha = SHA1.Create())
            {
                baseKeySha1 = sha.ComputeHash(baseKeyBytes);
            }
            byte[] first16OfHash = new byte[16];
            Array.Copy(baseKeySha1, first16OfHash, 16);
            return first16OfHash;
        }
        private static byte[] AesEncrypt(string value, byte[] key, byte[] iv)
        {
            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentNullException("value");
            }
            if (key == null || key.Length == 0)
            {
                throw new ArgumentNullException("key");
            }
            if (iv == null || iv.Length == 0)
            {
                throw new ArgumentNullException("iv");
            }

            byte[] output;
            using (AesManaged aes = new AesManaged()
            {
                Key = key,
                IV = iv,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.ECB
            })
            using (MemoryStream ms = new MemoryStream())
            {
                ICryptoTransform ct = aes.CreateEncryptor(aes.Key, aes.IV);
                using (CryptoStream cs = new CryptoStream(ms, ct, CryptoStreamMode.Write))
                using (StreamWriter sw = new StreamWriter(cs))
                {
                    sw.Write(value);
                }

                output = ms.ToArray();
            }

            return output;
        }

        #endregion
    }
}