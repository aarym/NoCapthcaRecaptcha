using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Web;
using Newtonsoft.Json;

namespace NoCaptchaReCaptcha
{
    internal class NoCaptchaRequest
    {
        #region Properties

        public string SiteKey { get; private set; }
        public string SecretKey { get; private set; }
        public string ErrorMessage { get; private set; }
        
        #endregion

        public NoCaptchaRequest(string siteKey, string secretKey)
        {
            SiteKey = siteKey;
            SecretKey = secretKey;
        }

        #region Methods

        public bool ValidateResponse()
        {
            var formResponse = this.GetNoCaptchaFormResponse();
            var url = string.Format(NoCaptchaSettings.RecaptchaApiUrlFormat, this.SecretKey, formResponse);

            var request = WebRequest.Create(url);

            using (var objStream = request.GetResponse().GetResponseStream())
            {
                if (objStream != null)
                {
                    using (var objReader = new StreamReader(objStream))
                    {
                        var googleResults = objReader.ReadToEnd();
                        var recaptchaResult = JsonConvert.DeserializeObject<ReCaptchaResponse>(googleResults);

                        if (!recaptchaResult.Success)
                            this.ErrorMessage = this.GetResponseErrorMessage(recaptchaResult);

                        return recaptchaResult.Success;
                    }
                }
            }
           
            return false;
        }
        private string GetNoCaptchaFormResponse()
        {
            return HttpContext.Current.Request.Form[NoCaptchaSettings.RecaptchaFormResponseKey];
        }
        private string GetResponseErrorMessage(ReCaptchaResponse response)
        {
            IList<string> errors = new List<string>();
            if (!response.Success && response.ErrorCodes == null)
            {
                errors.Add("Google Recaptcha: Unspecified Error");
            }
            else
            {
                foreach (string error in response.ErrorCodes)
                {
                    switch (error)
                    {
                        case "missing-input-secret":
                            errors.Add("Google Recaptcha: The secret parameter is missing");
                            break;
                        case "invalid-input-secret":
                            errors.Add("Google Recaptcha: The secret parameter is invalid or malformed");
                            break;
                        case "missing-input-response":
                            errors.Add("Google Recaptcha: Please tick the \"I'm not a robot\" checkbox");
                            break;
                        case "invalid-input-response":
                            errors.Add("Google Recaptcha: The response parameter is invalid or malformed");
                            break;
                        default:
                            errors.Add(error);
                            break;
                    }
                }
            }

            return string.Join(", ", errors);
        }

        #endregion
    }
}
