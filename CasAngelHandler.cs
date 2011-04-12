#region License

/*
 * Copyright © 2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#endregion

using System;
using System.Collections.Specialized;
using System.Configuration;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Text;
using System.Web;
using System.Web.Security;
using System.Xml;
using DotNetCasClient;

namespace CasAngelClient
{
    /// <summary>
    /// CasAngelClient provides Jasig CAS Authentiction for the Angel Learning Managment Suite
    /// http://www.blackboard.com/Platforms/Learn/Products/ANGEL-Edition.aspx
    /// </summary>
    public sealed class CasAngelHandler : IHttpHandler
    {
        // Web.conf appSettings prefix
        private const string CAS_ANGEL_CLIENT = "CasAngelClient";

        /// <summary>
        /// URL of CAS ClearPass extention
        /// </summary>
        private static readonly string ClearPassUrl;

        /// <summary>
        /// Angel API User - system/admin user authorized to use the Angel API.
        /// </summary>
        private static readonly string AngelApiUser;

        /// <summary>
        /// Angel API Password
        /// </summary>
        private static readonly string AngelApiPassword;

        /// <summary>
        /// URL for Angel REST API, e.g. https://hostname/api/default.asp
        /// </summary>
        private static readonly string AngelApiUrl;

        /// <summary>
        /// CasAngelClient can be configured to use CAS ClearPass and validate the users credentials
        /// on the AngelApi AUTHENTICATION_PASS call.  Set AngelApiValidate to false to bypass the ClearPass
        /// call and the sets VALIDATE=0 for the API call.  This is useful if you are not sync'ing 
        /// passwords bewteen CAS primary authentication and Angel.
        /// </summary>
        private static readonly bool AngelApiValidate;

        /// <summary>
        /// Bootstrap configuration from Web.conf.
        /// </summary>
        static CasAngelHandler()
        {

            AngelApiValidate = Convert.ToBoolean(ConfigurationManager.AppSettings.Get(CAS_ANGEL_CLIENT + ".AngelApiValidate"));
            if (AngelApiValidate)
            {
                ClearPassUrl = ConfigurationManager.AppSettings.Get(CAS_ANGEL_CLIENT + ".ClearPassUrl");
                if (String.IsNullOrEmpty(ClearPassUrl))
                {
                    throw new ConfigurationErrorsException(
                        "ClearPassUrl is missing. It must be set in <appSettings> section of <web.conf>.  Example: <add key=\"CasAngelClient.ClearPassUrl\" value=\"https://cashostname/cas/clearPass\"/>");
                }
            }

            AngelApiUrl = ConfigurationManager.AppSettings.Get(CAS_ANGEL_CLIENT + ".AngelApiUrl");
            if (String.IsNullOrEmpty(AngelApiUrl))
            {
                throw new ConfigurationErrorsException(
                    "AngelApiUrl is missing. It must be set in <appSettings> section of <web.conf>.  Example: <add key=\"CasAngelClient.AngelApiUrl\" value=\"https://angelhost/api/default.asp\"/>");
            }

            AngelApiUser = ConfigurationManager.AppSettings.Get(CAS_ANGEL_CLIENT + ".AngelApiUser");
            if (String.IsNullOrEmpty(AngelApiUrl))
            {
                throw new ConfigurationErrorsException(
                    "AngelApiUser is missing. It must be set in <appSettings> section of <web.conf>.  Example: <add key=\"CasAngelClient.AngelApiUrl\" value=\"username\"/>");
            }

            AngelApiPassword = ConfigurationManager.AppSettings.Get(CAS_ANGEL_CLIENT + ".AngelApiPassword");
            if (String.IsNullOrEmpty(AngelApiUrl))
            {
                throw new ConfigurationErrorsException(
                    "AngelApiPassword is missing. It must be set in <appSettings> section of <web.conf>.  Example: <add key=\"CasAngelClient.AngelApiPassword\" value=\"password\"/>");
            }

            // This is setting is neccesary when using untrusted certificates, typically in a development or testing.  This effects the entire application context.
            string skipCertValidation = ConfigurationManager.AppSettings.Get(CAS_ANGEL_CLIENT + "skipCertValidation");
            if (!String.IsNullOrEmpty(skipCertValidation) && bool.Parse(skipCertValidation))
            {
                ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(delegate { return true; });
            }
        }

        /// <summary>
        /// This handler can be used for another request, as no state information is preserved per request.
        /// </summary>
        public bool IsReusable
        {
            get { return true; }
        }

        /// <summary>
        /// Using CAS ProxyTickets and the ClearPass extention for CAS, CasAngelClient retrieves
        /// the users credentials, POSTs them to the Angel REST API ATHENICATION_PASS, retrieves
        /// a SSO token and URL and redirect's the user to Angel.
        /// </summary>
        /// <param name="context"></param>
        public void ProcessRequest(HttpContext context)
        {
            // Make sure we have an authenticated user
            if (!context.User.Identity.IsAuthenticated)
            {
                throw new HttpException(500, "HttpContext.Current.User is not authenticated.  Check that the DotNetCasClient is mapped and configured correctly in <web.conf>");
            }

            // Get clear text pasword via ClassPass if we are using AngelApiValidate
            string clearPass = "";
            if (AngelApiValidate)
            {

                // Retrieve a Proxy Ticket for ClearPass
                string proxyTicket = CasAuthentication.GetProxyTicketIdFor(ClearPassUrl);

                // Get the Password from ClearPass
                string clearPassResponse;
                WebClient clearPassWebClient = null;
                StreamReader reader = null;
                try
                {
                    clearPassWebClient = new WebClient();
                    clearPassWebClient.QueryString = new NameValueCollection
                                                         {{"ticket", proxyTicket}, {"service", ClearPassUrl}};
                    reader = new StreamReader(clearPassWebClient.OpenRead(ClearPassUrl));
                    clearPassResponse = reader.ReadToEnd();
                }
                catch (Exception ex)
                {
                    throw new HttpException(500,
                                            "Error getting response from clearPass at URL: " + ClearPassUrl + ". " +
                                            ex.Message, ex);
                }
                finally
                {
                    if (reader != null)
                    {
                        reader.Dispose();
                    }
                    if (clearPassWebClient != null)
                    {
                        clearPassWebClient.Dispose();
                    }
                }

                clearPass = GetTextForElement(clearPassResponse, "cas:credentials");
                if (String.IsNullOrEmpty(clearPass))
                {
                    throw new HttpException(500,
                                            "cas:credientials not found in clearPassResponse.  Check CAS server logs for errors.  Make sure SSL certs are trusted.");
                }
            }

            // Authenticate against Angel and retrieve redirect URL
            string strPost = "APIACTION=AUTHENTICATION_PASS&APIUSER=" + AngelApiUser
                             + "&APIPWD=" + AngelApiPassword
                             + "&USER=" + context.User.Identity.Name
                             + "&PASSWORD=" + clearPass
                             + "&VALIDATE=" + (AngelApiValidate ? "1" : "0"); // validate forces Angel to check users credentials
            string angelApiResponse = PerformHttpPost(AngelApiUrl, strPost, false);
            string redirectUrl = GetTextForElement(angelApiResponse, "success");
            if (String.IsNullOrEmpty(redirectUrl))
            {
                throw new HttpException(500, "Angel AUTHENTICATION_PASS failed for user: " + context.User.Identity.Name + ".  AngelAPI Error: " + GetTextForElement(angelApiResponse, "error"));
            }
            FormsAuthentication.SignOut();
            context.Response.Redirect(redirectUrl);
        }

        /// <summary>
        /// Parses an XML string for a specified element and returns the context as a string
        /// </summary>
        /// <param name="xmlString">the xml to be parsed</param>
        /// <param name="qualifiedElementName">the element to match, qualified with namespace</param>
        /// <returns>the text value of the element, or null if no element if found</returns>
        private static string GetTextForElement(string xmlString, string qualifiedElementName)
        {
            if (String.IsNullOrEmpty(xmlString))
            {
                throw new ArgumentNullException(xmlString);
            }

            if (String.IsNullOrEmpty(qualifiedElementName))
            {
                throw new ArgumentNullException(qualifiedElementName);
            }
                

            string elementText = null;
            var readerSettings = new XmlReaderSettings();
            readerSettings.ConformanceLevel = ConformanceLevel.Auto;
            readerSettings.IgnoreWhitespace = true;
            using (XmlReader xmlReader = XmlReader.Create(new StringReader(xmlString), readerSettings))
            {
                if (xmlReader.ReadToFollowing(qualifiedElementName))
                {
                    elementText = xmlReader.ReadElementContentAsString();
                }
            }
            return elementText;
        }


        /// <summary>
        /// Executes an HTTP POST against the Url specified with the supplied post data, 
        /// returning the entire response body in string form.
        /// </summary>
        /// <param name="url">The URL to post to</param>
        /// <param name="postData">The x-www-form-urlencoded data to post to the URL</param>
        /// <param name="requireHttp200">
        /// Boolean indicating whether or not to return 
        /// null if the repsonse status code is not 200 (OK).
        /// </param>
        /// <returns>
        /// The response body or null if the response status is required to 
        /// be 200 (OK) but is not
        /// </returns>
        private static string PerformHttpPost(string url, string postData, bool requireHttp200)
        {
            string responseBody = null;

            var request = (HttpWebRequest) WebRequest.Create(url);
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.ContentLength = Encoding.UTF8.GetByteCount(postData);

            using (var requestWriter = new StreamWriter(request.GetRequestStream()))
            {
                requestWriter.Write(postData);
            }

            using (var response = (HttpWebResponse) request.GetResponse())
            {
                using (Stream responseStream = response.GetResponseStream())
                {
                    if (responseStream != null)
                    {
                        using (var responseReader = new StreamReader(responseStream))
                        {
                            responseBody = responseReader.ReadToEnd();
                        }
                    }
                }
            }

            return responseBody;
        }
    }
}

