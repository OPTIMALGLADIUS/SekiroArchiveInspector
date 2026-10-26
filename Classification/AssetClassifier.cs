using System.Text;

namespace SekiroArchiveInspector.Classification;

public static class AssetClassifier
{
    private const int HeaderLength = 64;

    public static ClassificationResult Classify(string filePath)
    {
        byte[] header = ReadHeader(filePath);

        AssetFormat format = DetectFormat(header);

        return new ClassificationResult
        {
            FilePath = filePath,
            Format = format,
            DetectionMethod = format == AssetFormat.Unknown
                ? "No known signature matched"
                : "Header signature",

            HeaderHex = Convert.ToHexString(header),

            HeaderAscii = ToPrintableAscii(header),

            Notes = format == AssetFormat.Unknown
                ? "Unknown format; inspect header and surrounding structure."
                : "Signature match only; structural validation is still required."
        };
    }

    private static byte[] ReadHeader(string filePath)
    {
        using FileStream stream = File.OpenRead(filePath);

        byte[] buffer = new byte[HeaderLength];

        int bytesRead = stream.Read(buffer, 0, buffer.Length);

        return buffer[..bytesRead];
    }

    private static AssetFormat DetectFormat(byte[] header)
    {
        if (StartsWithAscii(header, "DCX"))
            return AssetFormat.DCX;

        if (StartsWithAscii(header, "DDS "))
            return AssetFormat.DDS;

        if (StartsWithAscii(header, "TPF"))
            return AssetFormat.TPF;

        if (StartsWithAscii(header, "FLVER"))
            return AssetFormat.FLVER;

        if (StartsWithAscii(header, "TAE"))
            return AssetFormat.TAE;

        if (StartsWithAscii(header, "HKX"))
            return AssetFormat.HKX;

        if (StartsWithAscii(header, "BND"))
            return AssetFormat.Binder;

        return AssetFormat.Unknown;
    }

    private static bool StartsWithAscii(
        byte[] data,
        string signature)
    {
        byte[] signatureBytes = Encoding.ASCII.GetBytes(signature);

        if (data.Length < signatureBytes.Length)
            return false;

        return data.AsSpan(0, signatureBytes.Length)
            .SequenceEqual(signatureBytes);
    }

    private static string ToPrintableAscii(byte[] data)
    {
        return new string(data.Select(b =>
            b >= 32 && b <= 126
                ? (char)b
                : '.').ToArray());
    }
}
