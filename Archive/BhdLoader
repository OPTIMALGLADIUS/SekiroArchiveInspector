using System.IO;
using System.Text;
using SoulsFormats;
using UXM;

namespace SekiroArchiveInspector.Archive;

public static class BhdLoader
{
    public static BHD5 Load(
        string bhdPath,
        string key)
    {
        byte[] magic = new byte[4];

        using (FileStream file = File.OpenRead(bhdPath))
        {
            if (file.Read(magic, 0, magic.Length) != magic.Length)
            {
                throw new InvalidDataException(
                    "BHD header is too short.");
            }
        }

        bool encrypted =
            Encoding.ASCII.GetString(magic) != "BHD5";

        if (encrypted)
        {
            using var decrypted =
                CryptographyUtility.DecryptRsa(
                    bhdPath,
                    key);

            return BHD5.Read(
                decrypted,
                BHD5.Game.DarkSouls3);
        }

        return BHD5.Read(
            bhdPath,
            BHD5.Game.DarkSouls3);
    }
}
