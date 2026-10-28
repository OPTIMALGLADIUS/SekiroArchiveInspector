using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using SoulsFormats;

namespace SekiroArchiveInspector.Extraction;

public static class Bnd4ExtractionService
{
    private sealed class EntryReport
    {
        public string SourceArchive { get; set; } = "";
        public int EntryId { get; set; }
        public string? OriginalName { get; set; }
        public string OutputFile { get; set; } = "";
        public long SizeBytes { get; set; }
    }

    private sealed class ArchiveReport
    {
        public string SourceArchive { get; set; } = "";
        public int EntryCount { get; set; }
        public string Status { get; set; } = "";
        public string? Error { get; set; }
        public List<EntryReport> Entries { get; set; } = new();
    }

    private sealed class RunReport
    {
        public DateTimeOffset StartedAtUtc { get; set; }
        public DateTimeOffset CompletedAtUtc { get; set; }
        public int ArchivesFound { get; set; }
        public int ArchivesSucceeded { get; set; }
        public int ArchivesFailed { get; set; }
        public int EntriesExtracted { get; set; }
        public List<ArchiveReport> Archives { get; set; } = new();
    }

    public static int Run(string[] args)
    {
        if (args.Length != 3)
        {
            Console.Error.WriteLine(
                "Usage: --extract-bnd4 <inputDir> <outputDir>");
            return 2;
        }

        string inputDir = Path.GetFullPath(args[1]);
        string outputDir = Path.GetFullPath(args[2]);

        if (!Directory.Exists(inputDir))
        {
            Console.Error.WriteLine($"Input directory not found: {inputDir}");
            return 2;
        }

        if (IsSameOrChild(inputDir, outputDir))
        {
            Console.Error.WriteLine(
                "Output directory must be outside the input directory.");
            return 2;
        }

        Directory.CreateDirectory(outputDir);

        string reportPath = Path.Combine(outputDir, "bnd4-extraction.json");

        var report = new RunReport
        {
            StartedAtUtc = DateTimeOffset.UtcNow
        };

        try
        {
            string[] files = Directory
                .EnumerateFiles(inputDir, "*.decompressed.bin",
                    SearchOption.AllDirectories)
                .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            report.ArchivesFound = files.Length;

            foreach (string path in files)
            {
                string relative = Path.GetRelativePath(inputDir, path);
                string archiveName = Path.GetFileNameWithoutExtension(
                    Path.GetFileNameWithoutExtension(path));

                var archiveReport = new ArchiveReport
                {
                    SourceArchive = relative
                };

                try
                {
                    byte[] bytes = File.ReadAllBytes(path);

                    string headerHex = Convert.ToHexString(
					    bytes.AsSpan(0, Math.Min(bytes.Length, 64)));
					string headerAscii = new string(
					    bytes.Take(Math.Min(bytes.Length, 64))
					        .Select(b => b >= 32 && b <= 126 ? (char)b : '.')
					        .ToArray());

                    if (bytes.Length < 4 ||
                        System.Text.Encoding.ASCII.GetString(bytes, 0, 4)
                            != "BND4")
                    {
                        Console.Error.WriteLine();
					    Console.Error.WriteLine("====== NON-BND4 PAYLOAD ======");
					    Console.Error.WriteLine($"File: {relative}");
					    Console.Error.WriteLine($"Size: {bytes.Length} bytes");
					    Console.Error.WriteLine($"Header hex: {headerHex}");
					    Console.Error.WriteLine($"Header ASCII: {headerAscii}");
					    Console.Error.WriteLine("==============================");
					    
                        throw new InvalidDataException(
                            "Payload does not begin with the BND4 signature.");
                    }

                    BND4 binder = BND4.Read(bytes);

                    string archiveOutputDir = Path.Combine(
                        outputDir,
                        Path.GetDirectoryName(relative) ?? "",
                        archiveName);

                    Directory.CreateDirectory(archiveOutputDir);

                    var usedNames = new HashSet<string>(
                        StringComparer.OrdinalIgnoreCase);

                    foreach (BinderFile entry in binder.Files)
                    {
                        string originalName = entry.Name ?? "";
                        string fileName = MakeSafeFileName(originalName);

                        if (string.IsNullOrWhiteSpace(fileName))
                            fileName = $"entry_{entry.ID:D6}.bin";

                        string uniqueName = fileName;
                        int duplicate = 1;

                        while (!usedNames.Add(uniqueName))
                        {
                            string stem = Path.GetFileNameWithoutExtension(fileName);
                            string extension = Path.GetExtension(fileName);
                            uniqueName = $"{stem}_{duplicate++}{extension}";
                        }

                        string destination = Path.GetFullPath(
                            Path.Combine(archiveOutputDir, uniqueName));

                        if (!IsSameOrChild(archiveOutputDir, destination))
                            throw new InvalidDataException(
                                "An entry output path escaped its archive directory.");

                        byte[] entryBytes = entry.Bytes
                            ?? throw new InvalidDataException(
                                $"Entry {entry.ID} has null data.");

                        File.WriteAllBytes(destination, entryBytes);

                        archiveReport.Entries.Add(new EntryReport
                        {
                            SourceArchive = relative,
                            EntryId = entry.ID,
                            OriginalName = originalName,
                            OutputFile = destination,
                            SizeBytes = entryBytes.LongLength
                        });
                    }

                    archiveReport.EntryCount = archiveReport.Entries.Count;
                    archiveReport.Status = "Succeeded";
                    report.ArchivesSucceeded++;
                    report.EntriesExtracted += archiveReport.EntryCount;

                    Console.WriteLine(
                        $"OK: {relative} -> {archiveReport.EntryCount} entries");
                }
                catch (Exception ex)
                {
                    archiveReport.Status = "Failed";
                    archiveReport.Error =
                        $"{ex.GetType().Name}: {ex.Message}";
                    report.ArchivesFailed++;

                    Console.Error.WriteLine(
                        $"FAILED: {relative}: {archiveReport.Error}");
                }

                report.Archives.Add(archiveReport);
            }

            if (files.Length == 0)
            {
                Console.Error.WriteLine(
                    $"No *.decompressed.bin files found in {inputDir}");
                return 1;
            }

            return report.ArchivesFailed == 0 ? 0 : 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"BND4 extraction failed: {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
        finally
        {
            report.CompletedAtUtc = DateTimeOffset.UtcNow;

            try
            {
                File.WriteAllText(
                    reportPath,
                    JsonSerializer.Serialize(report,
                        new JsonSerializerOptions { WriteIndented = true }));

                Console.WriteLine();
                Console.WriteLine("====== BND4 EXTRACTION SUMMARY ======");
                Console.WriteLine($"Archives found    : {report.ArchivesFound}");
                Console.WriteLine($"Archives succeeded: {report.ArchivesSucceeded}");
                Console.WriteLine($"Archives failed   : {report.ArchivesFailed}");
                Console.WriteLine($"Entries extracted : {report.EntriesExtracted}");
                Console.WriteLine($"Report            : {reportPath}");
                Console.WriteLine("=====================================");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(
                    $"Could not write BND4 report: {ex.Message}");
            }
        }
    }

    private static string MakeSafeFileName(string name)
    {
        string normalized = name.Replace('\\', '/');
        string leaf = normalized.Split('/').LastOrDefault() ?? "";

        foreach (char c in Path.GetInvalidFileNameChars())
            leaf = leaf.Replace(c, '_');

        // Also guard against Windows reserved path characters.
        foreach (char c in new[] { '<', '>', ':', '"', '|', '?', '*' })
            leaf = leaf.Replace(c, '_');

        return leaf.Trim().TrimEnd('.');
    }

    private static bool IsSameOrChild(string parent, string candidate)
    {
        string p = Path.GetFullPath(parent)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string c = Path.GetFullPath(candidate)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        if (string.Equals(p, c, StringComparison.OrdinalIgnoreCase))
            return true;

        return c.StartsWith(p + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase);
    }
}
