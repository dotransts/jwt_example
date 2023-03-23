using Jwt_Exammple;

var header = new Header
{
    Alg = "HS256",
    Typ = "JWT"
};

var claims = new Dictionary<string, string>();
claims.Add("isAdmin", "true");

var payload = new Payload
{
    Claims = claims
};

var jwt = JwtHelper.MakeJwt(header, payload, "quack");
Console.WriteLine(jwt);

var result = JwtHelper.VerifyJwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.dvr6c1h8Rip6qtE8AQ__0DXfpaZMB6zKL3Hzt8iVisE", "quack");
Console.WriteLine(result); //output True