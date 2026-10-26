using System.Globalization;

namespace SekiroArchiveInspector.Archive;

public static class HashParser
{
    public static bool TryParseHash(
        string hashText,
        out ulong hash)
    {
        string normalized = hashText.StartsWith(
            "0x",
            StringComparison.OrdinalIgnoreCase)
                ? hashText[2..]
                : hashText;

        return ulong.TryParse(
            normalized,
            NumberStyles.HexNumber,
            CultureInfo.InvariantCulture,
            out hash);
    }
}
