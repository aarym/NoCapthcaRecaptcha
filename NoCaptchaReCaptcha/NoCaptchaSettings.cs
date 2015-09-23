namespace NoCaptchaReCaptcha
{
    public class NoCaptchaSettings
    {
        public const string RecaptchaApiScript = "https://www.google.com/recaptcha/api.js";
        public const string RecaptchaFormResponseKey = "g-recaptcha-response";
        public const string RecaptchaCssClass = "g-recaptcha";
        public const string RecaptchaApiUrlFormat = @"https://www.google.com/recaptcha/api/siteverify?secret={0}&response={1}";

        public enum NoCaptchaTheme
        {
            Light,
            Dark
        }
        public enum NoCaptchaType
        {
            Image,
            Audio
        }
        public enum NoCaptchaSize
        {
            Normal,
            Compact
        }
    }
}
