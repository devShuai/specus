using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;

namespace ShuaiTunnel.Client.PeerMesh;

internal static class PeerKeyStore
{
    private const string DirectoryName = ".shuai-tunnel";
    private const string PublicKeyFileName = "peer-public.x25519";
    private const string PrivateKeyFileName = "peer-private.x25519";
    private static readonly object Sync = new();

    public static string PublicKeyBase64(ILogger logger)
    {
        try
        {
            return KeyMaterial().PublicKeyBase64;
        }
        catch (Exception ex) when (ex is CryptographicException or PlatformNotSupportedException or IOException or UnauthorizedAccessException)
        {
            logger.LogWarning("生成 peer mesh X25519 公钥失败: {Message}", ex.Message);
            return "";
        }
    }

    public static PeerKeyMaterial KeyMaterial()
    {
        lock (Sync)
        {
            var directory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                DirectoryName);
            var publicKeyPath = Path.Combine(directory, PublicKeyFileName);
            var privateKeyPath = Path.Combine(directory, PrivateKeyFileName);
            if (File.Exists(publicKeyPath) && File.Exists(privateKeyPath))
            {
                var existingPublic = File.ReadAllText(publicKeyPath, Encoding.UTF8).Trim();
                var existingPrivate = File.ReadAllText(privateKeyPath, Encoding.UTF8).Trim();
                if (!string.IsNullOrWhiteSpace(existingPublic) && !string.IsNullOrWhiteSpace(existingPrivate))
                {
                    return new PeerKeyMaterial(existingPublic, existingPrivate);
                }
            }

            Directory.CreateDirectory(directory);
            var keyMaterial = PeerCrypto.GenerateKeyMaterial();
            File.WriteAllText(publicKeyPath, keyMaterial.PublicKeyBase64, Encoding.UTF8);
            File.WriteAllText(privateKeyPath, keyMaterial.PrivateKeyBase64, Encoding.UTF8);
            return keyMaterial;
        }
    }
}

internal sealed record PeerKeyMaterial(string PublicKeyBase64, string PrivateKeyBase64);
