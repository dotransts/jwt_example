using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace Jwt_Exammple;

public class JwtHelper
{
    static DefaultContractResolver contractResolver = new DefaultContractResolver
    {
        NamingStrategy = new CamelCaseNamingStrategy()
    };

    private static string SerializeObject(object obj)
    {
        return JsonConvert.SerializeObject(obj, new JsonSerializerSettings()
        {
            ContractResolver = contractResolver,
            Formatting = Formatting.Indented
        });
    }

    public static string MakeJwt(Header header, Payload payload, string secretKey)
    {
        var headerJson = SerializeObject(header);
        var payloadJson = SerializeObject(payload.Claims);

        var base64Header = Base64UrlEncode(headerJson);
        var base64Payload = Base64UrlEncode(payloadJson);

        var signature = GenerateSignature(base64Header, base64Payload, secretKey);

        return $"{base64Header}.{base64Payload}.{signature}";
    }

    private static string GenerateSignature(string base64Header, string base64Payload, string secretKey)
    {
        var cipherText = $"{base64Header}.{base64Payload}";
        HMACSHA256 hmacsha256 = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey));
        var hashResult = hmacsha256.ComputeHash(Encoding.UTF8.GetBytes(cipherText));
        return Base64UrlEncode(hashResult);
    }

    private static string Base64UrlEncode(string someString)
    {
        var bytes = Encoding.UTF8.GetBytes(someString);
        return Base64UrlEncode(bytes);
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        var base64 = System.Convert.ToBase64String(bytes);
        var base64Url = base64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return base64Url;
    }

    public static bool VerifyJwt(string jwt, string secretKey)
    {
        var chunks = jwt.Split('.', StringSplitOptions.RemoveEmptyEntries);

        //get the header
        var header = JsonConvert.DeserializeObject<Header>(Base64UrlDecode(chunks[0]));
        //get all the claims back
        var payload = new Payload
        {
            Claims = JsonConvert.DeserializeObject<Dictionary<string, string>>(Base64UrlDecode(chunks[1]))
        };

        if (header.Alg != "HS256")
        {
            return false;
        }

        //we only need to generate the signature again and match with the signature in the jwt to verify it.
        var signature = GenerateSignature(chunks[0], chunks[1], secretKey);
        return signature == chunks[2];
    }

    //Thanks to this StackOverflow (answer)[https://stackoverflow.com/a/26354677]
    public static string Base64UrlDecode(string encodedString)
    {
        string incoming = encodedString
            .Replace('_', '/').Replace('-', '+');
        switch (incoming.Length % 4)
        {
            case 2: incoming += "=="; break;
            case 3: incoming += "="; break;
        }

        byte[] bytes = Convert.FromBase64String(incoming);
        string originalText = Encoding.ASCII.GetString(bytes);
        return originalText;
    }
}

public struct Header
{
    public string Alg { set; get; }
    public string Typ { set; get; }
}

public struct Payload
{
    public Dictionary<string, string> Claims { set; get; }
}