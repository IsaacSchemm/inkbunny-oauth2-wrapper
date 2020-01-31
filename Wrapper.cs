using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System.Net;
using System.Web;
using System.Text;

namespace InkbunnyOAuthWrapper {
    /// <summary>
    /// A set of Azure Functions endpoints that let OAuth2 clients obtain an Inkbunny username and sid from a user.
    /// </summary>
    public static class Wrapper {
        /// <summary>
        /// Gets the client secret for the given client ID from the Azure Functions configuration or local.settings.json file.
        /// </summary>
        /// <param name="clientId">The client ID</param>
        /// <returns>The client secret, or null if not found</returns>
        private static string GetClientSecret(string clientId) {
            if (clientId == null)
                return null;
            else if (!int.TryParse(clientId, out int i))
                return null;
            else
                return Environment.GetEnvironmentVariable($"ClientSecret_{i}", EnvironmentVariableTarget.Process);
        }

        /// <summary>
        /// Encrypts a string using the client secret.
        /// </summary>
        /// <param name="clientSecret">The client secret</param>
        /// <param name="val">The string to encrypt</param>
        /// <returns>A base-16 encoded encrypted string</returns>
        private static string Encrypt(string clientSecret, string val) {
            byte[] key = Convert.FromBase64String(clientSecret);

            string enc = AESGCM.SimpleEncrypt(val, key);
            return Uri.EscapeDataString(enc);
        }

        /// <summary>
        /// Decrypts a string using the client secret.
        /// </summary>
        /// <param name="clientSecret">The client secret</param>
        /// <param name="enc">A base-16 encoded encrypted string</param>
        /// <returns>The original string</returns>
        private static string Decrypt(string clientSecret, string enc) {
            byte[] key = Convert.FromBase64String(clientSecret);

            string dec = AESGCM.SimpleDecrypt(enc, key);
            return dec;
        }

        /// <summary>
        /// OAuth2 authorization endpoint.
        /// 
        /// Required parameters:
        /// * response_type (must be "code")
        /// * client_id (must correspond to a client secret in the Azure Functions configuration or local.settings.json)
        /// * redirect_uri
        /// 
        /// Optional parameters:
        /// * state
        /// 
        /// Ignored parameters:
        /// * scope
        /// </summary>
        [FunctionName("auth")]
        public static IActionResult Auth([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = null)] HttpRequest req) {
            string response_type = req.Query["response_type"];
            if (response_type != "code")
                return new BadRequestObjectResult(new { error = "The response_type is invalid or missing." });

            string client_id = req.Query["client_id"];
            string client_secret = GetClientSecret(client_id);
            if (client_secret == null)
                return new BadRequestObjectResult(new { error = "The client_id is invalid or missing." });

            string redirect_uri = req.Query["redirect_uri"];
            if (Uri.TryCreate(redirect_uri, UriKind.Absolute, out Uri redirect_uri_parsed) == false)
                return new BadRequestObjectResult(new { error = "The redirect_uri is invalid or missing." });

            StringBuilder hidden_inputs = new StringBuilder();
            hidden_inputs.AppendLine($"<input type='hidden' name='client_id' value='{HttpUtility.HtmlAttributeEncode(client_id)}' />");
            hidden_inputs.AppendLine($"<input type='hidden' name='redirect_uri' value='{HttpUtility.HtmlAttributeEncode(redirect_uri)}' />");

            string state = req.Query["state"];
            if (state != null)
                hidden_inputs.AppendLine($"<input type='hidden' name='state' value='{HttpUtility.HtmlAttributeEncode(state)}' />");

            string html = string.Format(@"<!DOCTYPE html>
<html>
    <head>
        <title>Inkbunny OAuth2 Wrapper</title>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css' integrity='sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T' crossorigin='anonymous'>
    </head>
<body class='m-2'>
    <p>
        Enter your Inkbunny credentials below.<br />
        To use the API, ""Enable API Access"" must be turned on in your <a href='https://inkbunny.net/account.php' target='_blank'>Inkbunny account settings.</a>
    </p>
    <form action='postback' method='post' class='col-md-6'>
        {0}
        <div class='form-group'>
            <label for='username'>Username</label>
            <input type='text' id='username' name='username' class='form-control' />
        </div>
        <div class='form-group'>
            <label for='password'>Password</label>
            <input type='password' id='password' name='password' class='form-control' />
        </div>
        <input type='submit' value='Submit' class='btn btn-primary' />
    </form>
    <hr />
    <p class='font-weight-bold'>This page is not part of Inkbunny. By entering your API key, you are giving {1} and {2} access to your account.</p>
    <hr />
    <p class='small'>
        <a href='https://github.com/IsaacSchemm/inkbunny-oauth2-wrapper' target='_blank'>
            View source on GitHub
        </a>
    </p>
</body>
</html>", hidden_inputs.ToString(), WebUtility.HtmlEncode(req.Host.Host), redirect_uri_parsed.Host);
            return new FileContentResult(Encoding.UTF8.GetBytes(html), "text/html; charset=utf-8");
        }

        /// <summary>
        /// Process an API key entry by the user and redirect to the redirect_uri.
        /// 
        /// Two URL parameters will be added:
        /// * code - an encrypted object containing the sid and user_id (encrypted using the client secret)
        /// * state - a copy of the state parameter sent with the /auth request, if any
        /// </summary>
        [FunctionName("postback")]
        public static async Task<IActionResult> Postback([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req) {
            string client_id = req.Form["client_id"];
            string client_secret = GetClientSecret(client_id);
            if (client_secret == null)
                return new BadRequestResult();

            string redirect_uri = req.Form["redirect_uri"];
            if (redirect_uri == null)
                return new BadRequestResult();

            var uriBuilder = new UriBuilder(redirect_uri);
            var query = HttpUtility.ParseQueryString(uriBuilder.Query);

            string username = req.Form["username"];
            if (username == null)
                return new BadRequestResult();

            string password = req.Form["password"];
            if (password == null)
                return new BadRequestResult();

            var hreq = WebRequest.CreateHttp("https://inkbunny.net/api_login.php");
            hreq.Method = "POST";
            hreq.ContentType = "application/x-www-form-urlencoded";
            using (var reqStream = await hreq.GetRequestStreamAsync()) {
                using var sw = new StreamWriter(reqStream);
                await sw.WriteAsync($"username={Uri.EscapeDataString(username)}&");
                await sw.WriteAsync($"password={Uri.EscapeDataString(password)}&");
                await sw.WriteAsync($"output_mode=json");
            }
            using var resp = await hreq.GetResponseAsync();
            using var respStream = resp.GetResponseStream();
            using var sr = new StreamReader(respStream);
            string json = await sr.ReadToEndAsync();

            var err = JsonConvert.DeserializeAnonymousType(json, new { error_message = "" });
            if (err.error_message != null) {
                string html = string.Format(@"<!DOCTYPE html>
<html>
    <head>
        <title>Inkbunny OAuth2 Wrapper</title>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css' integrity='sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T' crossorigin='anonymous'>
    </head>
<body class='m-2'>
    <p>
        {0}
    </p>
    <p>
        <a href='#' onclick='history.back();' class='btn btn-primary'>Go back</a>
    </p>
</body>
</html>", WebUtility.HtmlEncode(err.error_message));
                return new FileContentResult(Encoding.UTF8.GetBytes(html), "text/html; charset=utf-8");
            }

            var resp_obj = JsonConvert.DeserializeAnonymousType(json, new {
                sid = "",
                user_id = 0L,
                ratingsmask = ""
            });

            query["code"] = Encrypt(client_secret, JsonConvert.SerializeObject(new {
                s = resp_obj.sid,
                i = resp_obj.user_id,
                r = resp_obj.ratingsmask,
                u = username
            }));

            string state = req.Form["state"];
            if (state != null)
                query["state"] = state;

            uriBuilder.Query = query.ToString();
            return new RedirectResult(uriBuilder.ToString());
        }

        /// <summary>
        /// OAuth2 token request endpoint.
        /// 
        /// Required parameters:
        /// * grant_type (must be authorization_code)
        /// * code (the encrypted API key from the prior step)
        /// * client_id
        /// * client_secret
        /// 
        /// Ignored parameters:
        /// * redirect_uri
        /// </summary>
        /// <param name="req"></param>
        /// <returns></returns>
        [FunctionName("token")]
        public static IActionResult Token([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req) {
            string client_id = req.Form["client_id"];
            if (client_id == null)
                return new OkObjectResult(new {
                    error = "unauthorized_client",
                    error_description = "client_id is missing"
                });

            string client_secret = req.Form["client_secret"];
            if (client_secret == null || client_secret != GetClientSecret(client_id))
                return new OkObjectResult(new {
                    error = "unauthorized_client",
                    error_description = "client_secret is missing or does not match"
                });

            string grant_type = req.Form["grant_type"];
            if (grant_type != "authorization_code")
                return new OkObjectResult(new {
                    error = "unsupported_grant_type",
                    error_description = "Only authorization_code is supported"
                });

            string code = req.Form["code"];
            if (string.IsNullOrEmpty(code))
                return new OkObjectResult(new {
                    error = "invalid_request",
                    error_description = "code is missing or invalid"
                });

            try {
                string sid_json = Decrypt(client_secret, code);

                var user_obj = JsonConvert.DeserializeAnonymousType(sid_json, new {
                    s = "",
                    i = 0L,
                    r = "",
                    u = ""
                });

                return new OkObjectResult(new {
                    access_token = user_obj.s,
                    token_type = "inkbunny",
                    user_id = user_obj.u,
                    ratingsmask = user_obj.r,
                    username = user_obj.u
                });
            } catch (JsonReaderException) {
                return new OkObjectResult(new {
                    error = "invalid_request",
                    error_description = "code is missing or invalid"
                });
            }
        }
    }
}
