using System.Security.Cryptography;
using System.Text;

namespace Netex24;

public static class Netex24ClientSignatureService
{
    public static string GetRequestSignature(string request, string id, string nonce, string privateKey)
    {
        var signatureRawData = $"{request}{id}{nonce}".ToLowerInvariant().Replace("{}", "");
        var signatureRawDataBytes = Encoding.UTF8.GetBytes(signatureRawData);
        using var sha512 = new SHA512Managed();
        var signatureRawDataHash = sha512.ComputeHash(signatureRawDataBytes);
        var secretKeyByteArray = Convert.FromBase64String(privateKey);

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportECPrivateKey(secretKeyByteArray, out _);
        var signatureBytes = ecdsa.SignHash(signatureRawDataHash);

        var signatureHex = BitConverter.ToString(signatureBytes).Replace("-", "");

        return $"{signatureHex}:{id}:{nonce}";
    }
}