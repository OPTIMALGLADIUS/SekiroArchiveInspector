using System;
using System.Linq;
using System.Text;

namespace SekiroArchiveInspector.Archive;

public sealed record ContentClassification(
    string Category,
    string DetectedType,
    string Confidence,
    int PriorityScore,
    string Reason)
{
    public string HeaderHex { get; init; } = "";
    public double EntropyBitsPerByte { get; init; }
}

public static class ContentClassifier
{
    private const int HeaderPreviewLength = 32;

    public static ContentClassification Classify(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (data.Length == 0)
        {
            return Result(
                data, "Empty", "Empty file", "High", 5,
                "The file contains no bytes.");
        }

        // FromSoftware compression wrappers.
        if (AsciiAt(data, 0, "DCX\0"))
        {
            return Result(
                data, "Compression", "FromSoftware DCX container",
                "High", 95,
                "DCX signature detected. Inspect or decompress the wrapper to identify its payload.");
        }

        if (AsciiAt(data, 0, "DCP\0"))
        {
            return Result(
                data, "Compression", "FromSoftware DCP container",
                "High", 90,
                "DCP signature detected. The wrapped payload has not been inspected.");
        }

        // FromSoftware archive and resource formats.
        if (AsciiAt(data, 0, "BND3"))
        {
            return Result(
                data, "Archive", "BND3",
                "High", 90,
                "BND3 signature detected.");
        }

        if (AsciiAt(data, 0, "BND4"))
        {
            return Result(
                data, "Archive", "BND4",
                "High", 90,
                "BND4 signature detected.");
        }

        if (AsciiAt(data, 0, "BHD5"))
        {
            return Result(
                data, "Archive", "BHD5",
                "High", 90,
                "BHD5 archive-header signature detected.");
        }

        if (AsciiAt(data, 0, "BDF3"))
        {
            return Result(
                data, "Archive", "BDF3",
                "High", 85,
                "BDF3 archive-data signature detected.");
        }

        if (AsciiAt(data, 0, "BDF4"))
        {
            return Result(
                data, "Archive", "BDF4",
                "High", 85,
                "BDF4 archive-data signature detected.");
        }

        if (AsciiAt(data, 0, "TPF\0"))
        {
            return Result(
                data, "Texture", "TPF texture package",
                "High", 90,
                "TPF signature detected.");
        }

        if (AsciiAt(data, 0, "FLVER"))
        {
            return Result(
                data, "Model", "Possible FLVER model",
                "Medium", 75,
                "FLVER text signature detected; validate the version and structure before treating it as a valid model.");
        }

        // Textures and images.
        if (StartsWith(data, 0x44, 0x44, 0x53, 0x20))
        {
            return Result(
                data, "Texture", "DDS",
                "High", 95, "DDS texture signature.");
        }

        if (StartsWith(data, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A))
        {
            return Result(
                data, "Image", "PNG",
                "High", 90, "PNG signature.");
        }

        if (StartsWith(data, 0xFF, 0xD8, 0xFF))
        {
            return Result(
                data, "Image", "JPEG",
                "High", 85, "JPEG signature.");
        }

        if (StartsWith(data, 0xAB, 0x4B, 0x54, 0x58, 0x20, 0x32, 0x30, 0xBB))
        {
            return Result(
                data, "Texture", "KTX 2",
                "High", 90, "KTX 2 signature.");
        }

        if (StartsWith(data, 0x4B, 0x54, 0x58, 0x20, 0x31, 0x31, 0xBB, 0x0D))
        {
            return Result(
                data, "Texture", "KTX",
                "High", 85, "KTX signature.");
        }

        // Audio and video.
        if (AsciiAt(data, 0, "OggS"))
        {
            return Result(
                data, "Audio", "Ogg container",
                "High", 80,
                "Ogg signature detected; codec not determined.");
        }

        if (AsciiAt(data, 0, "RIFF") && AsciiAt(data, 8, "WAVE"))
        {
            return Result(
                data, "Audio", "WAV",
                "High", 80, "RIFF/WAVE signature.");
        }

        if (AsciiAt(data, 0, "RIFF") && AsciiAt(data, 8, "AVI "))
        {
            return Result(
                data, "Video", "AVI",
                "High", 75, "RIFF/AVI signature.");
        }

        if (AsciiAt(data, 4, "ftyp"))
        {
            return Result(
                data, "Media", "ISO Base Media container",
                "Medium", 65,
                "Possible MP4 or related media container.");
        }

        if (AsciiAt(data, 0, "ID3"))
        {
            return Result(
                data, "Audio", "MP3 with ID3 tag",
                "High", 80, "ID3 signature.");
        }

        if (StartsWith(data, 0xFF, 0xFB) ||
            StartsWith(data, 0xFF, 0xF3) ||
            StartsWith(data, 0xFF, 0xF2))
        {
            return Result(
                data, "Audio", "Possible MP3 frame",
                "Medium", 65,
                "Possible MPEG audio frame header.");
        }

        // Common archive formats.
        if (StartsWith(data, 0x50, 0x4B, 0x03, 0x04) ||
            StartsWith(data, 0x50, 0x4B, 0x05, 0x06) ||
            StartsWith(data, 0x50, 0x4B, 0x07, 0x08))
        {
            return Result(
                data, "Archive", "ZIP",
                "High", 70, "ZIP signature.");
        }

        if (AsciiAt(data, 0, "glTF"))
        {
            return Result(
                data, "Model", "Binary glTF (GLB)",
                "High", 85, "GLB signature.");
        }

        // Text and structured data.
        if (LooksLikeText(data))
        {
            string text = Encoding.UTF8.GetString(data).TrimStart('\uFEFF', ' ', '\t', '\r', '\n');

            if (text.StartsWith("{") || text.StartsWith("["))
            {
                return Result(
                    data, "Structured data", "Possible JSON",
                    "Low", 45,
                    "Text begins with a JSON-like character; JSON syntax was not validated.");
            }

            if (text.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase) ||
                text.StartsWith("<"))
            {
                return Result(
                    data, "Structured data", "Possible XML or markup",
                    "Low", 45,
                    "Text begins with a markup-like character; syntax was not validated.");
            }

            return Result(
                data, "Text", "Text or script",
                "Low", 35,
                "Bytes appear to contain readable text.");
        }

        // Do not mistake high entropy for proof of encryption or compression.
        double entropy = CalculateEntropy(data);

        string reason = entropy >= 7.5
            ? "No recognized signature. Sample has high byte entropy; compression or encryption is possible but unconfirmed."
            : "No recognized signature matched. Use the header preview and metadata for further investigation.";

        return Result(
            data, "Unknown", "Unknown binary format",
            "Low", 10, reason);
    }

    private static ContentClassification Result(
        byte[] data,
        string category,
        string type,
        string confidence,
        int score,
        string reason)
    {
        int length = Math.Min(data.Length, HeaderPreviewLength);

        string headerHex = length == 0
            ? ""
            : Convert.ToHexString(data.AsSpan(0, length));

        return new ContentClassification(
            category,
            type,
            confidence,
            score,
            reason)
        {
            HeaderHex = headerHex,
            EntropyBitsPerByte = Math.Round(CalculateEntropy(data), 4)
        };
    }

    private static bool StartsWith(byte[] data, params byte[] signature)
    {
        if (data.Length < signature.Length)
            return false;

        return data.AsSpan(0, signature.Length).SequenceEqual(signature);
    }

    private static bool AsciiAt(byte[] data, int offset, string value)
    {
        if (offset < 0 || data.Length - offset < value.Length)
            return false;

        for (int i = 0; i < value.Length; i++)
        {
            if (data[offset + i] != (byte)value[i])
                return false;
        }

        return true;
    }

    private static bool LooksLikeText(byte[] data)
    {
        int length = Math.Min(data.Length, 4096);

        if (length == 0)
            return false;

        int printable = 0;

        for (int i = 0; i < length; i++)
        {
            byte b = data[i];

            if (b == 0)
                return false;

            if (b == 9 || b == 10 || b == 13 ||
                (b >= 32 && b <= 126) || b >= 128)
            {
                printable++;
            }
        }

        return printable * 100 / length >= 85;
    }

    private static double CalculateEntropy(byte[] data)
    {
        if (data.Length == 0)
            return 0;

        // Sampling the first 64 KiB keeps analysis inexpensive for large files.
        int length = Math.Min(data.Length, 65_536);
        Span<int> counts = stackalloc int[256];

        for (int i = 0; i < length; i++)
            counts[data[i]]++;

        double entropy = 0;

        for (int i = 0; i < counts.Length; i++)
        {
            if (counts[i] == 0)
                continue;

            double probability = (double)counts[i] / length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }
}
