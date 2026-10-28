using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using SoulsFormats;

namespace SekiroArchiveInspector.Extraction;

public static class TpfExtractionService
{
    private sealed class TextureReport
    {
        public int Index { get; set; }
        public string Name { get; set; } = "";
        public string OutputFile { get; set; } = "";
        public long OriginalByteLength { get; set; }
        public long OutputByteLength { get; set; }
        public string OutputFormat { get; set; } = "";
        public string Status { get; set; } = "";
        public string? Error { get; set; }
    }

    private sealed class ExtractionReport
    {
        public string InputFile { get; set; } = "";
        public long InputSize { get; set; }
        public string CompressionType { get; set; } = "None";
        public string DecompressedTpfPath { get; set; } = "";
        public long DecompressedTpfSize { get; set; }
        public string TpfPlatform { get; set; } = "";
        public int TextureCount { get; set; }
        public int TexturesSucceeded { get; set; }
        public int TexturesFailed { get; set; }
        public List<TextureReport> Textures { get; set; } = new();
    }

    public static int Run(string[] args)
    {
        if (args.Length != 3)
        {
            Console.Error.WriteLine(
                "Usage: --extract-tpf <inputFile> <outputDir>");
            return 2;
        }

        string inputPath = Path.GetFullPath(args[1]);
        string outputDir = Path.GetFullPath(args[2]);

        if (!File.Exists(inputPath))
        {
            Console.Error.WriteLine($"Input file not found: {inputPath}");
            return 2;
        }

        try
        {
            Directory.CreateDirectory(outputDir);

            byte[] inputBytes = File.ReadAllBytes(inputPath);
            byte[] tpfBytes = inputBytes;
            string compressionType = "None";

            if (DCX.Is(inputBytes))
            {
                tpfBytes = DCX.Decompress(inputBytes, out var compressionInfo);
                compressionType = compressionInfo.Type.ToString();
            }

            if (tpfBytes.Length < 4 ||
                Encoding.ASCII.GetString(tpfBytes, 0, 4) != "TPF\0")
            {
                string header = Convert.ToHexString(
                    tpfBytes.AsSpan(0, Math.Min(tpfBytes.Length, 32)));

                throw new InvalidDataException(
                    $"Expected a TPF package after decompression. " +
                    $"Actual header: {header}");
            }

            string baseName = Path.GetFileNameWithoutExtension(inputPath);
            string tpfPath = Path.Combine(outputDir, baseName + ".tpf");
            string textureDir = Path.Combine(outputDir, "textures");

            Directory.CreateDirectory(textureDir);
            File.WriteAllBytes(tpfPath, tpfBytes);

            TPF tpf = TPF.Read(tpfBytes);

            var report = new ExtractionReport
            {
                InputFile = inputPath,
                InputSize = inputBytes.LongLength,
                CompressionType = compressionType,
                DecompressedTpfPath = tpfPath,
                DecompressedTpfSize = tpfBytes.LongLength,
                TpfPlatform = tpf.Platform.ToString(),
                TextureCount = tpf.Textures.Count
            };

            var usedNames = new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

            for (int i = 0; i < tpf.Textures.Count; i++)
            {
                var texture = tpf.Textures[i];

                string textureName = string.IsNullOrWhiteSpace(texture.Name)
                    ? $"texture_{i:D4}"
                    : texture.Name;

                string safeName = MakeSafeFileName(textureName);

                if (string.IsNullOrWhiteSpace(safeName))
                    safeName = $"texture_{i:D4}";

                string extension = ".dds";
                string destination;

                var textureReport = new TextureReport
                {
                    Index = i,
                    Name = textureName,
                    OriginalByteLength = texture.Bytes.LongLength
                };

                try
                {
                    // Headerize reconstructs a standard texture file.
                    // Some platforms/formats may produce another extension.
                    byte[] outputBytes =
                        Headerizer.Headerize(texture, out extension);

                    if (string.IsNullOrWhiteSpace(extension))
                        extension = ".bin";

                    string fileName = $"{i:D4}_{safeName}{extension}";
                    string uniqueName = fileName;
                    int duplicate = 1;

                    while (!usedNames.Add(uniqueName))
                    {
                        uniqueName =
                            $"{i:D4}_{safeName}_{duplicate++}{extension}";
                    }

                    destination = Path.Combine(textureDir, uniqueName);

                    File.WriteAllBytes(destination, outputBytes);

                    textureReport.OutputFile = destination;
                    textureReport.OutputByteLength = outputBytes.LongLength;
                    textureReport.OutputFormat = extension.TrimStart('.');
                    textureReport.Status = "Succeeded";

                    report.TexturesSucceeded++;

                    Console.WriteLine(
                        $"OK: [{i + 1}/{tpf.Textures.Count}] " +
                        $"{textureName} -> {Path.GetFileName(destination)}");
                }
                catch (Exception ex)
                {
                    textureReport.OutputFormat = extension.TrimStart('.');
                    textureReport.Status = "Failed";
                    textureReport.Error =
                        $"{ex.GetType().Name}: {ex.Message}";

                    report.TexturesFailed++;

                    Console.Error.WriteLine(
                        $"FAILED: texture {i} ({textureName}): " +
                        textureReport.Error);
                }

                report.Textures.Add(textureReport);
            }

            string reportPath = Path.Combine(
                outputDir, "tpf-extraction.json");

            File.WriteAllText(
                reportPath,
                JsonSerializer.Serialize(
                    report,
                    new JsonSerializerOptions { WriteIndented = true }));

            Console.WriteLine();
            Console.WriteLine("====== TPF EXTRACTION SUMMARY ======");
            Console.WriteLine($"Input:              {inputPath}");
            Console.WriteLine($"Compression:        {compressionType}");
            Console.WriteLine($"Textures found:     {report.TextureCount}");
            Console.WriteLine($"Textures succeeded: {report.TexturesSucceeded}");
            Console.WriteLine($"Textures failed:    {report.TexturesFailed}");
            Console.WriteLine($"TPF package:        {tpfPath}");
            Console.WriteLine($"Texture directory:  {textureDir}");
            Console.WriteLine($"Report:             {reportPath}");
            Console.WriteLine("====================================");

            return report.TexturesFailed == 0 &&
                   report.TexturesSucceeded > 0 ? 0 : 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"TPF extraction failed: {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }

    private static string MakeSafeFileName(string name)
    {
        string result = name;

        foreach (char c in Path.GetInvalidFileNameChars())
            result = result.Replace(c, '_');

        foreach (char c in new[] { '<', '>', ':', '"', '/', '\\', '|', '?', '*' })
            result = result.Replace(c, '_');

        return result.Trim().TrimEnd('.');
    }
}
