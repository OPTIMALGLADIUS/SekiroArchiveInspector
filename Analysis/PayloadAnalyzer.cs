using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using SoulsFormats;
using SekiroArchiveInspector.Archive;

namespace SekiroArchiveInspector.Analysis;

public static class PayloadAnalyzer
{
    private const int MaxDecompressionLayers = 8;

    private sealed class AnalysisReport
    {
        public DateTimeOffset StartedAtUtc { get; set; }
        public DateTimeOffset CompletedAtUtc { get; set; }
        public double DurationSeconds { get; set; }

        public string InputDirectory { get; set; } = "";
        public string OutputDirectory { get; set; } = "";

        public int TotalFiles { get; set; }
        public int Analyzed { get; set; }
        public int Decompressed { get; set; }
        public int Failed { get; set; }

        public List<FileAnalysis> Files { get; set; } = new();
    }

    private sealed class FileAnalysis
    {
        public string RelativePath { get; set; } = "";
        public long OriginalSizeBytes { get; set; }
        public string OriginalSha256 { get; set; } = "";
        public string OriginalHeaderHex { get; set; } = "";
        public double OriginalEntropyBitsPerByte { get; set; }

        public string OriginalCategory { get; set; } = "";
        public string OriginalDetectedType { get; set; } = "";
        public string OriginalConfidence { get; set; } = "";

        public bool IsCompressedContainer { get; set; }
        public int DecompressionLayers { get; set; }
        public List<string> CompressionTypes { get; set; } = new();

        public long? FinalPayloadSizeBytes { get; set; }
        public string? FinalPayloadSha256 { get; set; }
        public string? FinalPayloadHeaderHex { get; set; }
        public double? FinalPayloadEntropyBitsPerByte { get; set; }

        public string? FinalPayloadCategory { get; set; }
        public string? FinalPayloadDetectedType { get; set; }
        public string? FinalPayloadConfidence { get; set; }

        public string Status { get; set; } = "";
        public string? OutputFile { get; set; }
        public string? Error { get; set; }
    }

    public static int Run(string[] args)
    {
        if (args.Length != 3)
        {
            Console.Error.WriteLine(
                "Usage: --analyze-payloads <inputDir> <outputDir>");
            return 2;
        }

        string inputDirectory = Path.GetFullPath(args[1]);
        string outputDirectory = Path.GetFullPath(args[2]);

        if (!Directory.Exists(inputDirectory))
        {
            Console.Error.WriteLine(
                $"Input directory not found: {inputDirectory}");
            return 2;
        }

        // Prevent recursive discovery of the analyzer's own output.
        if (IsSameOrChildDirectory(inputDirectory, outputDirectory))
        {
            Console.Error.WriteLine(
                "Output directory must be outside the input directory. " +
                "This prevents generated files from being analyzed as input.");
            return 2;
        }

        Directory.CreateDirectory(outputDirectory);

        string reportPath = Path.Combine(
            outputDirectory, "payload-analysis.json");

        var report = new AnalysisReport
        {
            StartedAtUtc = DateTimeOffset.UtcNow,
            InputDirectory = inputDirectory,
            OutputDirectory = outputDirectory
        };

        var timer = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            // Snapshot the input list before writing any output.
            string[] files = Directory
                .EnumerateFiles(
                    inputDirectory, "*.bin", SearchOption.AllDirectories)
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            report.TotalFiles = files.Length;

            Console.WriteLine($"Input: {inputDirectory}");
            Console.WriteLine($"Output: {outputDirectory}");
            Console.WriteLine($"Report: {reportPath}");
            Console.WriteLine($"BIN files found: {files.Length}");
            Console.WriteLine();

            foreach (string filePath in files)
            {
                string relativePath = Path.GetRelativePath(
                    inputDirectory, filePath);

                var item = new FileAnalysis
                {
                    RelativePath = relativePath
                };

                try
                {
                    byte[] original = File.ReadAllBytes(filePath);
                    byte[] current = original;

                    ContentClassification originalClassification =
                        ContentClassifier.Classify(original);

                    item.OriginalSizeBytes = original.LongLength;
                    item.OriginalSha256 = ComputeSha256(original);
                    item.OriginalHeaderHex =
                        originalClassification.HeaderHex;
                    item.OriginalEntropyBitsPerByte =
                        originalClassification.EntropyBitsPerByte;

                    item.OriginalCategory =
                        originalClassification.Category;
                    item.OriginalDetectedType =
                        originalClassification.DetectedType;
                    item.OriginalConfidence =
                        originalClassification.Confidence;

                    bool changed = false;

                    // Repeatedly unwrap nested DCX/DCP containers.
                    // Each successful layer becomes the input for the next.
                    for (int layer = 1;
                         layer <= MaxDecompressionLayers;
                         layer++)
                    {
                        if (!DCX.Is(current))
                            break;

                        item.IsCompressedContainer = true;

                        byte[] decompressed;
                        DCX.CompressionInfo compression;

                        using (var input = new MemoryStream(
                                   current, writable: false))
                        {
                            decompressed = DCX.Decompress(
                                input, out compression);
                        }

                        if (decompressed.Length == 0)
                        {
                            throw new InvalidDataException(
                                $"Decompression layer {layer} returned " +
                                "an empty payload.");
                        }

                        item.CompressionTypes.Add(
                            compression.Type.ToString());

                        item.DecompressionLayers++;
                        current = decompressed;
                        changed = true;
                    }

                    if (changed)
                    {
                        // A remaining wrapper may indicate deeper nesting
                        // than the safety limit permits.
                        if (item.DecompressionLayers ==
                                MaxDecompressionLayers &&
                            DCX.Is(current))
                        {
                            throw new InvalidDataException(
                                $"Reached the maximum of " +
                                $"{MaxDecompressionLayers} decompression " +
                                "layers while another DCX/DCP wrapper remains.");
                        }

                        string relativeOutputPath =
                            GetDecompressedRelativePath(relativePath);

                        string finalPath = Path.GetFullPath(
                            Path.Combine(outputDirectory, relativeOutputPath));

                        // Ensure the generated path stays inside output.
                        if (!IsSameOrChildDirectory(
                                outputDirectory,
                                Path.GetDirectoryName(finalPath)!))
                        {
                            throw new InvalidDataException(
                                "Generated output path escaped the output directory.");
                        }

                        Directory.CreateDirectory(
                            Path.GetDirectoryName(finalPath)!);

                        File.WriteAllBytes(finalPath, current);

                        item.OutputFile = finalPath;
                        item.FinalPayloadSizeBytes = current.LongLength;
                        item.FinalPayloadSha256 = ComputeSha256(current);

                        ContentClassification finalClassification =
                            ContentClassifier.Classify(current);

                        item.FinalPayloadHeaderHex =
                            finalClassification.HeaderHex;
                        item.FinalPayloadEntropyBitsPerByte =
                            finalClassification.EntropyBitsPerByte;
                        item.FinalPayloadCategory =
                            finalClassification.Category;
                        item.FinalPayloadDetectedType =
                            finalClassification.DetectedType;
                        item.FinalPayloadConfidence =
                            finalClassification.Confidence;

                        item.Status = "Decompressed";
                        report.Decompressed++;
                    }
                    else
                    {
                        item.Status = "NoSupportedCompressionDetected";
                    }

                    report.Analyzed++;
                }
                catch (Exception ex)
                {
                    item.Status = "Failed";
                    item.Error = $"{ex.GetType().Name}: {ex.Message}";
                    report.Failed++;

                    Console.Error.WriteLine(
                        $"Failed: {relativePath}: {item.Error}");
                }

                report.Files.Add(item);

                if (report.Files.Count % 100 == 0 ||
                    report.Files.Count == files.Length)
                {
                    Console.WriteLine(
                        $"Progress: {report.Files.Count}/{files.Length} | " +
                        $"Decompressed: {report.Decompressed} | " +
                        $"Failed: {report.Failed}");
                }
            }

            return report.Failed == 0 ? 0 : 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"Payload analysis failed: {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
        finally
        {
            timer.Stop();

            report.CompletedAtUtc = DateTimeOffset.UtcNow;
            report.DurationSeconds = timer.Elapsed.TotalSeconds;

            try
            {
                File.WriteAllText(
                    reportPath,
                    JsonSerializer.Serialize(
                        report,
                        new JsonSerializerOptions
                        {
                            WriteIndented = true
                        }));

                Console.WriteLine();
                Console.WriteLine("====== PAYLOAD ANALYSIS SUMMARY ======");
                Console.WriteLine($"Files found    : {report.TotalFiles}");
                Console.WriteLine($"Analyzed       : {report.Analyzed}");
                Console.WriteLine($"Decompressed   : {report.Decompressed}");
                Console.WriteLine($"Failed         : {report.Failed}");
                Console.WriteLine(
                    $"Duration       : {report.DurationSeconds:F2} seconds");
                Console.WriteLine($"Report         : {reportPath}");
                Console.WriteLine("======================================");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(
                    $"Could not write analysis report: {ex.Message}");
            }
        }
    }

    private static string GetDecompressedRelativePath(
        string relativePath)
    {
        string directory = Path.GetDirectoryName(relativePath) ?? "";
        string fileName = Path.GetFileNameWithoutExtension(relativePath);

        // Keep the original relative folder layout but use a distinct name.
        string outputName = $"{fileName}.decompressed.bin";

        return Path.Combine(directory, outputName);
    }

    private static string ComputeSha256(byte[] data)
    {
        return Convert.ToHexString(SHA256.HashData(data));
    }

    private static bool IsSameOrChildDirectory(
        string parent,
        string candidate)
    {
        string normalizedParent = Path.GetFullPath(parent)
            .TrimEnd(Path.DirectorySeparatorChar,
                     Path.AltDirectorySeparatorChar);

        string normalizedCandidate = Path.GetFullPath(candidate)
            .TrimEnd(Path.DirectorySeparatorChar,
                     Path.AltDirectorySeparatorChar);

        if (string.Equals(
                normalizedParent,
                normalizedCandidate,
                StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        string prefix = normalizedParent + Path.DirectorySeparatorChar;

        return normalizedCandidate.StartsWith(
            prefix, StringComparison.OrdinalIgnoreCase);
    }
}
