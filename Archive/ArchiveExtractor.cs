using System;
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
            "Heuristic priority for follow-up analysis; not a measure of gameplay importance.";
        public List<ExtractionEntryReport> Entries { get; set; } = new();
        public List<ExtractionEntryReport> PriorityRanking { get; set; } = new();
    }

    private sealed class ExtractionEntryReport
    {
        public int EntryIndex { get; set; }
        public string Hash { get; set; } = "";
        public string OutputFile { get; set; } = "";
        public bool Success { get; set; }
        public long? OutputSizeBytes { get; set; }
        public string Category { get; set; } = "Unknown";
        public string DetectedType { get; set; } = "Not classified";
        public string ClassificationConfidence { get; set; } = "None";
        public int PriorityScore { get; set; }
        public string ClassificationReason { get; set; } = "";
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

        try
        {
            Console.WriteLine($"Archive: {archiveName}");
            Console.WriteLine($"BHD: {bhdPath}");
            Console.WriteLine($"BDT: {bdtPath}");
            Console.WriteLine($"Output: {outputDirectory}");
            Console.WriteLine($"Report: {reportPath}");
            Console.WriteLine();

            BHD5 archive = BhdLoader.Load(bhdPath, archiveKey);

            var entries = archive.Buckets
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

            using FileStream bdtStream = File.OpenRead(bdtPath);

            for (int i = 0; i < entries.Count; i++)
            {
                BHD5.FileHeader entry = entries[i];

                // Keep the original 16-digit hexadecimal representation.
                string hashName = entry.FileNameHash.ToString("X16");
                string outputPath = Path.Combine(
                    outputDirectory, $"{hashName}.bin");

                var item = new ExtractionEntryReport
                {
                    EntryIndex = i,
                    Hash = hashName,
                    OutputFile = outputPath
                };

                try
                {
                    byte[] data = entry.ReadFile(bdtStream);

                    // Classify the actual extracted bytes.
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

            return report.Failed == 0 ? 0 : 1;
        }
        catch (Exception ex)
        {
            report.Status = "FatalError";
            report.Failed++;

            Console.Error.WriteLine(
                $"Archive extraction failed: {ex.GetType().Name}: {ex.Message}");

            ExceptionUtility.PrintExceptionDetails(ex);

            return 1;
        }
        finally
        {
            timer.Stop();

            report.CompletedAtUtc = DateTimeOffset.UtcNow;
            report.DurationSeconds = timer.Elapsed.TotalSeconds;

            // Best-effort report writing, including after a fatal error.
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
                Console.WriteLine($"Duration      : {report.DurationSeconds:F2} seconds");
                Console.WriteLine($"Report        : {reportPath}");
                Console.WriteLine("========================================");
            }
            catch (Exception reportException)
            {
                Console.Error.WriteLine(
                    $"Could not write extraction report: {reportException.Message}");
            }
        }
    }
}
