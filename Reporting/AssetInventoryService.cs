using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SekiroArchiveInspector.Archive;

namespace SekiroArchiveInspector.Reporting;

public static class AssetInventoryService
{
    private sealed class Asset
    {
        public string RelativePath { get; set; } = "";
        public string FileName { get; set; } = "";
        public string Extension { get; set; } = "";
        public string Category { get; set; } = "";
        public string DetectedType { get; set; } = "";
        public string Confidence { get; set; } = "";
        public int PriorityScore { get; set; }
        public long SizeBytes { get; set; }
        public string Sha256 { get; set; } = "";
        public string HeaderHex { get; set; } = "";
        public double EntropyBitsPerByte { get; set; }
        public string Reason { get; set; } = "";
    }

    public static int Run(string[] args)
    {
        if (args.Length != 3)
        {
            Console.Error.WriteLine(
                "Usage: --inventory <inputDir> <outputDir>");
            return 2;
        }

        string input = Path.GetFullPath(args[1]);
        string output = Path.GetFullPath(args[2]);

        if (!Directory.Exists(input))
        {
            Console.Error.WriteLine($"Input directory not found: {input}");
            return 2;
        }

        if (IsSameOrChild(input, output) ||
            IsSameOrChild(output, input))
        {
            Console.Error.WriteLine(
                "Inventory output must be separate from the scanned directory.");
            return 2;
        }

        Directory.CreateDirectory(output);
        var assets = new List<Asset>();

        foreach (string path in Directory
                     .EnumerateFiles(input, "*", SearchOption.AllDirectories)
                     .OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var info = new FileInfo(path);
                int sampleLength = (int)Math.Min(info.Length, 65_536);
                byte[] sample = new byte[sampleLength];

                using (var stream = File.OpenRead(path))
                {
                    int offset = 0;
                    while (offset < sample.Length)
                    {
                        int read = stream.Read(
                            sample, offset, sample.Length - offset);
                        if (read == 0)
                            break;
                        offset += read;
                    }

                    if (offset != sample.Length)
                        Array.Resize(ref sample, offset);
                }

                var classification = ContentClassifier.Classify(sample);

                string sha256;
                using (var stream = File.OpenRead(path))
                    sha256 = Convert.ToHexString(SHA256.HashData(stream));

                assets.Add(new Asset
                {
                    RelativePath = Path.GetRelativePath(input, path),
                    FileName = Path.GetFileName(path),
                    Extension = Path.GetExtension(path),
                    Category = classification.Category,
                    DetectedType = classification.DetectedType,
                    Confidence = classification.Confidence,
                    PriorityScore = classification.PriorityScore,
                    SizeBytes = info.Length,
                    Sha256 = sha256,
                    HeaderHex = classification.HeaderHex,
                    EntropyBitsPerByte =
                        classification.EntropyBitsPerByte,
                    Reason = classification.Reason
                });
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(
                    $"Inventory warning: {path}: {ex.Message}");
            }
        }

        var summary = new
        {
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            InputDirectory = input,
            TotalFiles = assets.Count,
            TotalBytes = assets.Sum(a => a.SizeBytes),
            CountsByDetectedType = assets
                .GroupBy(a => a.DetectedType)
                .OrderBy(g => g.Key)
                .ToDictionary(g => g.Key, g => g.Count()),
            BytesByDetectedType = assets
                .GroupBy(a => a.DetectedType)
                .OrderBy(g => g.Key)
                .ToDictionary(g => g.Key, g => g.Sum(a => a.SizeBytes))
        };

        File.WriteAllText(
            Path.Combine(output, "asset-inventory.json"),
            JsonSerializer.Serialize(
                assets, new JsonSerializerOptions { WriteIndented = true }));

        File.WriteAllText(
            Path.Combine(output, "asset-inventory-summary.json"),
            JsonSerializer.Serialize(
                summary, new JsonSerializerOptions { WriteIndented = true }));

        string csvPath = Path.Combine(output, "asset-inventory.csv");

        using (var writer = new StreamWriter(
                   csvPath, false, new UTF8Encoding(true)))
        {
            writer.WriteLine(
                "RelativePath,FileName,Extension,Category,DetectedType," +
                "Confidence,PriorityScore,SizeBytes,Sha256,HeaderHex," +
                "EntropyBitsPerByte,Reason");

            foreach (Asset a in assets)
            {
                string[] fields =
                {
                    a.RelativePath, a.FileName, a.Extension, a.Category,
                    a.DetectedType, a.Confidence,
                    a.PriorityScore.ToString(),
                    a.SizeBytes.ToString(), a.Sha256, a.HeaderHex,
                    a.EntropyBitsPerByte.ToString(
                        System.Globalization.CultureInfo.InvariantCulture),
                    a.Reason
                };

                writer.WriteLine(string.Join(",", fields.Select(Csv)));
            }
        }

        Console.WriteLine("====== ASSET INVENTORY ======");
        Console.WriteLine($"Files scanned : {assets.Count}");
        Console.WriteLine($"Total bytes   : {summary.TotalBytes}");
        Console.WriteLine($"JSON          : {Path.Combine(output, "asset-inventory.json")}");
        Console.WriteLine($"CSV           : {csvPath}");
        Console.WriteLine($"Summary       : {Path.Combine(output, "asset-inventory-summary.json")}");
        Console.WriteLine("=============================");

        return 0;
    }

    private static string Csv(string value) =>
        "\"" + value.Replace("\"", "\"\"") + "\"";

    private static bool IsSameOrChild(string parent, string candidate)
    {
        string p = Path.GetFullPath(parent).TrimEnd(
            Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string c = Path.GetFullPath(candidate).TrimEnd(
            Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        return string.Equals(p, c, StringComparison.OrdinalIgnoreCase) ||
               c.StartsWith(p + Path.DirectorySeparatorChar,
                   StringComparison.OrdinalIgnoreCase);
    }
}
