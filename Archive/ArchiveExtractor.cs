using System;
using System.IO;
using System.Linq;
using UXM;
using SoulsFormats;
using SekiroArchiveInspector.Utilities;

namespace SekiroArchiveInspector.Archive;

public static class ArchiveExtractor
{
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
            Console.Error.WriteLine(
                $"BHD file not found: {bhdPath}");

            return 2;
        }

        if (!File.Exists(bdtPath))
        {
            Console.Error.WriteLine(
                $"BDT file not found: {bdtPath}");

            return 2;
        }

        // Example: Data2.bhd -> Data2
        string archiveName =
            Path.GetFileNameWithoutExtension(bhdPath);

        if (!ArchiveKeys.SekiroKeys.TryGetValue(
                archiveName,
                out string? archiveKey))
        {
            Console.Error.WriteLine(
                $"No Sekiro RSA key is registered for archive '{archiveName}'.");

            return 2;
        }

        try
        {
            Directory.CreateDirectory(outputDirectory);

            Console.WriteLine($"Archive: {archiveName}");
            Console.WriteLine($"BHD: {bhdPath}");
            Console.WriteLine($"BDT: {bdtPath}");
            Console.WriteLine($"Output: {outputDirectory}");
            Console.WriteLine();

            // Load and decrypt the BHD if required.
            BHD5 archive = BhdLoader.Load(
                bhdPath,
                archiveKey);

            var entries = archive.Buckets
                .SelectMany(bucket => bucket)
                .ToList();

            if (entries.Count == 0)
            {
                Console.Error.WriteLine(
                    "The archive index contains no entries.");

                return 1;
            }

            Console.WriteLine(
                $"Archive contains {entries.Count} entries.");

            int succeeded = 0;
            int failed = 0;

            using FileStream bdtStream = File.OpenRead(bdtPath);

            for (int i = 0; i < entries.Count; i++)
            {
                BHD5.FileHeader entry = entries[i];

                string hashName =
                    entry.FileNameHash.ToString("X16");

                string outputPath = Path.Combine(
                    outputDirectory,
                    $"{hashName}.bin");

                try
                {
                    // SoulsFormats reads the entry using its archive
                    // metadata and handles the relevant entry decoding.
                    byte[] data = entry.ReadFile(bdtStream);

                    File.WriteAllBytes(outputPath, data);

                    succeeded++;

                    if ((i + 1) % 1000 == 0 ||
                        i + 1 == entries.Count)
                    {
                        Console.WriteLine(
                            $"Progress: {i + 1}/{entries.Count} | " +
                            $"Succeeded: {succeeded} | Failed: {failed}");
                    }
                }
                catch (Exception ex)
                {
                    failed++;

                    Console.Error.WriteLine(
                        $"Failed entry {hashName}: {ex.Message}");

                    ExceptionUtility.PrintExceptionDetails(ex);
                }
            }

            Console.WriteLine();
            Console.WriteLine("========== EXTRACTION SUMMARY ==========");
            Console.WriteLine($"Total entries : {entries.Count}");
            Console.WriteLine($"Succeeded     : {succeeded}");
            Console.WriteLine($"Failed        : {failed}");
            Console.WriteLine($"Output        : {outputDirectory}");
            Console.WriteLine("========================================");

            return failed == 0 ? 0 : 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"Archive extraction failed: {ex.GetType().Name}: {ex.Message}");

            ExceptionUtility.PrintExceptionDetails(ex);

            return 1;
        }
    }
}
