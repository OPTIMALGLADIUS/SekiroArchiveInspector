using System;
using System.Linq;
using System.Text;

namespace SekiroArchiveInspector.Archive;

public sealed record ContentClassification(
    string Category,
    string DetectedType,
    string Confidence,
    int PriorityScore,
    string Reason);

public static class ContentClassifier
{
    public static ContentClassification Classify(byte[] data)
    {
        if (data.Length == 0)
            return Result("Empty", "Empty file", "High", 5,
                "The file contains no bytes.");

        // Common image and texture formats.
        if (StartsWith(data, 0x44, 0x44, 0x53, 0x20))
            return Result("Texture", "DirectDraw Surface (DDS)",
                "High", 95, "DDS texture signature.");

        if (StartsWith(data, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A))
            return Result("Image", "PNG", "High", 75,
                "PNG signature.");

        if (StartsWith(data, 0xFF, 0xD8, 0xFF))
            return Result("Image", "JPEG", "High", 75,
                "JPEG signature.");

        if (StartsWith(data, 0x4B, 0x54, 0x58, 0x20, 0x31, 0x31, 0xBB, 0x0D))
            return Result("Texture", "KTX", "High", 90,
                "KTX texture signature.");

        if (StartsWith(data, 0xAB, 0x4B, 0x54, 0x58, 0x20, 0x32, 0x30, 0xBB))
            return Result("Texture", "KTX 2", "High", 90,
                "KTX 2 texture signature.");

        // Audio and video containers.
        if (AsciiAt(data, 0, "OggS"))
            return Result("Audio", "Ogg container", "High", 80,
                "Ogg signature; the contained codec is not yet verified.");

        if (AsciiAt(data, 0, "RIFF") && AsciiAt(data, 8, "WAVE"))
            return Result("Audio", "WAV", "High", 80,
                "RIFF/WAVE signature.");

        if (AsciiAt(data, 0, "RIFF") && AsciiAt(data, 8, "AVI "))
            return Result("Video", "AVI", "High", 65,
                "RIFF/AVI signature.");

        if (AsciiAt(data, 4, "ftyp"))
            return Result("Media", "ISO Base Media container",
                "Medium", 65, "Possible MP4 or related media container.");

        // Common archives and structured data.
        if (StartsWith(data, 0x50, 0x4B, 0x03, 0x04))
            return Result("Archive", "ZIP", "High", 45,
                "ZIP local-file-header signature.");

        if (AsciiAt(data, 0, "glTF"))
            return Result("Model", "Binary glTF (GLB)", "High", 90,
                "GLB signature.");

        if (AsciiAt(data, 0, "ID3"))
            return Result("Audio", "MP3 with ID3 tag", "High", 80,
                "ID3 signature.");

        if (StartsWith(data, 0xFF, 0xFB) ||
            StartsWith(data, 0xFF, 0xF3) ||
            StartsWith(data, 0xFF, 0xF2))
            return Result("Audio", "Possible MP3 frame", "Medium", 75,
                "Possible MPEG audio frame header.");

        // Text detection is deliberately conservative.
        if (LooksLikeText(data))
        {
            string text = Encoding.UTF8.GetString(data).TrimStart();

            if (text.StartsWith("{") || text.StartsWith("["))
                return Result("Structured data", "Possible JSON",
                    "Low", 60, "Text begins with a JSON-like character.");

            if (text.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase) ||
                text.StartsWith("<"))
                return Result("Structured data", "Possible XML or markup",
                    "Low", 60, "Text begins with a markup-like character.");

            return Result("Text", "Text or script", "Low", 40,
                "Bytes appear to contain readable text.");
        }

        return Result("Unknown", "Unknown binary format", "Low", 10,
            "No recognized signature matched.");
    }

    private static ContentClassification Result(
        string category,
        string type,
        string confidence,
        int score,
        string reason)
    {
        return new ContentClassification(
            category, type, confidence, score, reason);
    }

    private static bool StartsWith(byte[] data, params byte[] signature)
    {
        if (data.Length < signature.Length)
            return false;

        return signature
            .Select((value, index) => data[index] == value)
            .All(matches => matches);
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
        // Inspect only a prefix so very large files aren't scanned twice.
        int length = Math.Min(data.Length, 4096);
        int printable = 0;
        int examined = 0;

        for (int i = 0; i < length; i++)
        {
            byte b = data[i];

            if (b == 0)
                return false;

            examined++;

            if (b == 9 || b == 10 || b == 13 ||
                (b >= 32 && b <= 126) || b >= 128)
            {
                printable++;
            }
        }

        return examined > 0 && printable * 100 / examined >= 85;
    }
}
