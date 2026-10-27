using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using SoulsFormats;
using UXM;
using SekiroArchiveInspector.Utilities;

namespace SekiroArchiveInspector.Archive;

public static class ArchiveExtractor
{
    private sealed class ExtractionReport
    {
        public string ArchiveName { get; set; } = "";
        public string BhdPath { get; set; } = "";
        public string BdtPath { get; set; } = "";
        public string OutputDirectory { get; set; } = "";

        public DateTimeOffset StartedAtUtc { get; set; }
        public DateTimeOffset CompletedAtUtc { get; set; }
        public double DurationSeconds { get; set; }

        public int TotalEntries { get; set; }
        public int Succeeded { get; set; }
        public int Failed { get; set; }
        public string Status { get; set; } = "";

        public string RankingDescription { get; set; } =
            "Heuristic signature-based priority for follow-up analysis; " +
            "not a measure of gameplay importance or file validity.";

        public List<ExtractionEntryReport> Entries { get; set; } = new();
        public List<ExtractionEntryReport> PriorityRanking { get; set; } = new();
    }

    private sealed class ExtractionEntryReport
    {
        public int EntryIndex { get; set; }

        // Preserve all 16 hexadecimal digits, including leading zeroes.
        public string Hash { get; set; } = "";

        public string OutputFile { get; set; } = "";
        public bool Success { get; set; }
        public long? OutputSizeBytes { get; set; }

        // Metadata from BHD5.FileHeader.
        public long BdtFileOffset { get; set; }
        public int PaddedFileSize { get; set; }
        public long UnpaddedFileSize { get; set; }
        public bool HasAesKey { get; set; }
        public bool HasShaHash { get; set; }

        // Content classification.
        public string Category { get; set; } = "Unknown";
        public string DetectedType { get; set; } = "Not classified";
        public string ClassificationConfidence { get; set; } = "None";
        public int PriorityScore { get; set; }
        public string ClassificationReason { get; set; } = "";

        // Diagnostic data from ContentClassifier.
        public string HeaderHex { get; set; } = "";
        public double? EntropyBitsPerByte { get; set; }

        public string? Error { get; set; }
    }

    public static int RunSingle(string[] args)
    {
        Console.Error.WriteLine(
            "The --extract command has not been implemented yet.");

        return 2;
    }

    public static int RunAll(string[] args)
    {
        if (args.Length != 4)
        {
            Console.Error.WriteLine(
                "Usage: --extract-all <DataN.bhd> <DataN.bdt> <outputDir>");

            return 2;
        }

        string bhdPath = Path.GetFullPath(args[1]);
        string bdtPath = Path.GetFullPath(args[2]);
        string outputDirectory = Path.GetFullPath(args[3]);

        if (!File.Exists(bhdPath))
        {
            Console.Error.WriteLine($"BHD file not found: {bhdPath}");
            return 2;
        }

        if (!File.Exists(bdtPath))
        {
            Console.Error.WriteLine($"BDT file not found: {bdtPath}");
            return 2;
        }

        string archiveName = Path.GetFileNameWithoutExtension(bhdPath);

        if (!ArchiveKeys.SekiroKeys.TryGetValue(
                archiveName, out string? archiveKey))
        {
            Console.Error.WriteLine(
                $"No Sekiro RSA key is registered for archive '{archiveName}'.");

            return 2;
        }

        Directory.CreateDirectory(outputDirectory);

        string reportPath = Path.Combine(
            outputDirectory, "reports.json");

        var report = new ExtractionReport
        {
            ArchiveName = archiveName,
            BhdPath = bhdPath,
            BdtPath = bdtPath,
            OutputDirectory = outputDirectory,
            StartedAtUtc = DateTimeOffset.UtcNow
        };

        var timer = Stopwatch.StartNew();
        int exitCode = 1;

        try
        {
            Console.WriteLine($"Archive: {archiveName}");
            Console.WriteLine($"BHD: {bhdPath}");
            Console.WriteLine($"BDT: {bdtPath}");
            Console.WriteLine($"Output: {outputDirectory}");
            Console.WriteLine($"Report: {reportPath}");
            Console.WriteLine();

            BHD5 archive = BhdLoader.Load(bhdPath, archiveKey);

            List<BHD5.FileHeader> entries = archive.Buckets
                .SelectMany(bucket => bucket)
                .ToList();

            report.TotalEntries = entries.Count;

            if (entries.Count == 0)
            {
                report.Status = "NoEntries";

                Console.Error.WriteLine(
                    "The archive index contains no entries.");

                return 1;
            }

            Console.WriteLine(
                $"Archive contains {entries.Count} entries.");

            using FileStream bdtStream = new(
                bdtPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read);

            for (int i = 0; i < entries.Count; i++)
            {
                BHD5.FileHeader entry = entries[i];

                string hashName = entry.FileNameHash.ToString("X16");
                string outputPath = Path.Combine(
                    outputDirectory, $"{hashName}.bin");

                var item = new ExtractionEntryReport
                {
                    EntryIndex = i,
                    Hash = hashName,
                    OutputFile = outputPath,

                    BdtFileOffset = entry.FileOffset,
                    PaddedFileSize = entry.PaddedFileSize,
                    UnpaddedFileSize = entry.UnpaddedFileSize,
                    HasAesKey = entry.AESKey != null,
                    HasShaHash = entry.SHAHash != null
                };

                try
                {
                    byte[] data = ReadEntrySafely(entry, bdtStream);

                    ContentClassification classification =
                        ContentClassifier.Classify(data);

                    File.WriteAllBytes(outputPath, data);

                    item.Success = true;
                    item.OutputSizeBytes = data.LongLength;

                    item.Category = classification.Category;
                    item.DetectedType = classification.DetectedType;
                    item.ClassificationConfidence = classification.Confidence;
                    item.PriorityScore = classification.PriorityScore;
                    item.ClassificationReason = classification.Reason;
                    item.HeaderHex = classification.HeaderHex;
                    item.EntropyBitsPerByte =
                        classification.EntropyBitsPerByte;

                    report.Succeeded++;
                }
                catch (Exception ex)
                {
                    item.Success = false;
                    item.Error = $"{ex.GetType().Name}: {ex.Message}";
                    report.Failed++;

                    Console.Error.WriteLine(
                        $"Failed entry {hashName}: {item.Error}");

                    ExceptionUtility.PrintExceptionDetails(ex);
                }

                report.Entries.Add(item);

                if ((i + 1) % 1000 == 0 ||
                    i + 1 == entries.Count)
                {
                    Console.WriteLine(
                        $"Progress: {i + 1}/{entries.Count} | " +
                        $"Succeeded: {report.Succeeded} | " +
                        $"Failed: {report.Failed}");
                }
            }

            report.PriorityRanking = report.Entries
                .Where(item => item.Success)
                .OrderByDescending(item => item.PriorityScore)
                .ThenBy(item => item.Hash, StringComparer.Ordinal)
                .ToList();

            report.Status = report.Failed == 0
                ? "Completed"
                : "CompletedWithErrors";

            exitCode = report.Failed == 0 ? 0 : 1;
        }
        catch (Exception ex)
        {
            report.Status = "FatalError";
            report.Failed++;

            Console.Error.WriteLine(
                $"Archive extraction failed: {ex.GetType().Name}: {ex.Message}");

            ExceptionUtility.PrintExceptionDetails(ex);
            exitCode = 1;
        }
        finally
        {
            timer.Stop();

            report.CompletedAtUtc = DateTimeOffset.UtcNow;
            report.DurationSeconds = timer.Elapsed.TotalSeconds;

            try
            {
                string json = JsonSerializer.Serialize(
                    report,
                    new JsonSerializerOptions
                    {
                        WriteIndented = true,
                        DefaultIgnoreCondition =
                            JsonIgnoreCondition.WhenWritingNull
                    });

                File.WriteAllText(reportPath, json);

                Console.WriteLine();
                Console.WriteLine("========== EXTRACTION SUMMARY ==========");
                Console.WriteLine($"Total entries : {report.TotalEntries}");
                Console.WriteLine($"Succeeded     : {report.Succeeded}");
                Console.WriteLine($"Failed        : {report.Failed}");
                Console.WriteLine(
                    $"Duration      : {report.DurationSeconds:F2} seconds");
                Console.WriteLine($"Report        : {reportPath}");
                Console.WriteLine("========================================");
            }
            catch (Exception reportException)
            {
                Console.Error.WriteLine(
                    $"Could not write extraction report: " +
                    $"{reportException.Message}");

                if (exitCode == 0)
                    exitCode = 1;
            }
        }

        return exitCode;
    }

    private static byte[] ReadEntrySafely(
        BHD5.FileHeader entry,
        FileStream bdtStream)
    {
        if (entry.FileOffset < 0)
        {
            throw new InvalidDataException(
                $"Negative BDT offset: {entry.FileOffset}.");
        }

        if (entry.PaddedFileSize < 0)
        {
            throw new InvalidDataException(
                $"Negative padded file size: {entry.PaddedFileSize}.");
        }

        if (entry.FileOffset > bdtStream.Length ||
            entry.PaddedFileSize > bdtStream.Length - entry.FileOffset)
        {
            throw new InvalidDataException(
                $"Entry extends beyond the BDT file. " +
                $"Offset={entry.FileOffset}, " +
                $"Size={entry.PaddedFileSize}, " +
                $"BDT length={bdtStream.Length}.");
        }

        byte[] data = new byte[entry.PaddedFileSize];

        bdtStream.Position = entry.FileOffset;
        bdtStream.ReadExactly(data);

        // Match SoulsFormats BHD5.FileHeader.ReadFile behavior.
        entry.AESKey?.Decrypt(data);

        return data;
    }
}
