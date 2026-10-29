using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SekiroArchiveInspector.Archive;
using SoulsFormats;

namespace SekiroArchiveInspector.Extraction;

public static class RecursiveExtractionService
{
    private const int MaxDepth = 24;
    private const int MaxFiles = 100_000;
    private const long MaxFileBytes = 2L * 1024 * 1024 * 1024;

    private sealed record Work(string Path, string RelativePath, int Depth);

    private sealed class ItemReport
    {
        public string Source { get; set; } = "";
        public string Type { get; set; } = "";
        public string Status { get; set; } = "";
        public string Output { get; set; } = "";
        public int Depth { get; set; }
        public long InputBytes { get; set; }
        public long OutputBytes { get; set; }
        public string Sha256 { get; set; } = "";
        public int EntriesExtracted { get; set; }
        public string? Error { get; set; }
    }

    private sealed class RunReport
    {
        public DateTimeOffset StartedAtUtc { get; set; }
        public DateTimeOffset CompletedAtUtc { get; set; }
        public int FilesVisited { get; set; }
        public int ContainersExpanded { get; set; }
        public int EntriesExtracted { get; set; }
        public int Failures { get; set; }
        public List<ItemReport> Items { get; set; } = new();
    }

    public static int Run(string[] args)
    {
        if (args.Length != 3)
        {
            Console.Error.WriteLine(
                "Usage: --extract-recursive <inputDir> <outputDir>");
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
                "Input and output directories must be separate.");
            return 2;
        }

        Directory.CreateDirectory(output);

        var report = new RunReport
        {
            StartedAtUtc = DateTimeOffset.UtcNow
        };

        var queue = new Queue<Work>();

        foreach (string file in Directory
                     .EnumerateFiles(input, "*", SearchOption.AllDirectories)
                     .OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
        {
            queue.Enqueue(new Work(
                file, Path.GetRelativePath(input, file), 0));
        }

        // Avoid expanding identical containers repeatedly.
        var expandedHashes = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase);

        while (queue.Count > 0)
        {
            if (report.FilesVisited >= MaxFiles)
            {
                report.Failures++;
                report.Items.Add(new ItemReport
                {
                    Status = "SafetyLimit",
                    Error = $"Stopped at {MaxFiles} processed files."
                });
                break;
            }

            Work work = queue.Dequeue();
            report.FilesVisited++;

            var item = new ItemReport
            {
                Source = work.RelativePath,
                Depth = work.Depth
            };

            try
            {
                if (work.Depth > MaxDepth)
                    throw new InvalidDataException(
                        $"Maximum recursion depth ({MaxDepth}) exceeded.");

                var info = new FileInfo(work.Path);

                if (!info.Exists)
                    throw new FileNotFoundException(
                        "Queued file no longer exists.", work.Path);

                if (info.Length > MaxFileBytes)
                    throw new InvalidDataException(
                        $"File exceeds {MaxFileBytes} bytes.");

                byte[] bytes = File.ReadAllBytes(work.Path);
                item.InputBytes = bytes.LongLength;
                item.Sha256 = Convert.ToHexString(
                    SHA256.HashData(bytes));

                item.Type = ContentClassifier.Classify(bytes).DetectedType;

                // DCX: decompress, save the result, and inspect it next.
                if (Has(bytes, "DCX\0"))
                {
                    byte[] unpacked = DCX.Decompress(
                        bytes, out var compressionInfo);

                    string relative = AddSuffix(
                        work.RelativePath, ".decompressed");

                    string destination = SafePath(output, relative);
                    Directory.CreateDirectory(
                        Path.GetDirectoryName(destination)!);
                    File.WriteAllBytes(destination, unpacked);

                    item.Output = relative;
                    item.OutputBytes = unpacked.LongLength;
                    item.Status =
                        $"DecompressedDCX:{compressionInfo.Type}";

                    report.ContainersExpanded++;
                    report.Items.Add(item);

                    if (unpacked.Length > 0)
                        queue.Enqueue(new Work(
                            destination, relative, work.Depth + 1));

                    continue;
                }

                bool bnd4 = Has(bytes, "BND4");
                bool bnd3 = Has(bytes, "BND3");

                if (bnd4 || bnd3)
                {
                    if (!expandedHashes.Add(item.Sha256))
                    {
                        item.Status = "DuplicateContainerSkipped";
                        report.Items.Add(item);
                        continue;
                    }

                    // Both binder formats expose BinderFile entries in
                    // the expected SoulsFormats API. Verify BND3 at build.
                    IEnumerable<BinderFile> entries = bnd4
                        ? BND4.Read(bytes).Files
                        : BND3.Read(bytes).Files;

                    string containerRelative =
                        ContainerDirectory(work.RelativePath);
                    string containerDirectory =
                        SafePath(output, containerRelative);

                    Directory.CreateDirectory(containerDirectory);

                    var usedNames = new HashSet<string>(
                        StringComparer.OrdinalIgnoreCase);

                    long outputBytes = 0;
                    int count = 0;

                    foreach (BinderFile entry in entries)
                    {
                        string name = SafeName(entry.Name ?? "");

                        if (string.IsNullOrWhiteSpace(name))
                            name = $"entry_{entry.ID:D6}.bin";

                        string unique = UniqueName(name, usedNames);
                        byte[] entryBytes = entry.Bytes
                            ?? throw new InvalidDataException(
                                $"Binder entry {entry.ID} has null data.");

                        string destination =
                            SafePath(containerDirectory, unique);

                        File.WriteAllBytes(destination, entryBytes);

                        string relative = Path.GetRelativePath(
                            output, destination);

                        queue.Enqueue(new Work(
                            destination, relative, work.Depth + 1));

                        outputBytes += entryBytes.LongLength;
                        count++;
                    }

                    item.Output = containerRelative;
                    item.OutputBytes = outputBytes;
                    item.EntriesExtracted = count;
                    item.Status = bnd4 ? "ExtractedBND4" : "ExtractedBND3";

                    report.ContainersExpanded++;
                    report.EntriesExtracted += count;
                    report.Items.Add(item);

                    Console.WriteLine(
                        $"{item.Status}: {work.RelativePath} -> {count} entries");

                    continue;
                }

                // TPF: preserve the package and export individual textures.
                if (Has(bytes, "TPF\0"))
                {
                    string textureRelative =
                        ContainerDirectory(work.RelativePath) + "_textures";
                    string textureDirectory =
                        SafePath(output, textureRelative);

                    Directory.CreateDirectory(textureDirectory);

                    string package = SafePath(
                        textureDirectory,
                        Path.GetFileNameWithoutExtension(work.RelativePath)
                            + ".tpf");

                    File.WriteAllBytes(package, bytes);

                    TPF tpf = TPF.Read(bytes);
                    var usedNames = new HashSet<string>(
                        StringComparer.OrdinalIgnoreCase);

                    int succeeded = 0;
                    int failed = 0;

                    for (int i = 0; i < tpf.Textures.Count; i++)
                    {
                        var texture = tpf.Textures[i];

                        string name = SafeName(
                            string.IsNullOrWhiteSpace(texture.Name)
                                ? $"texture_{i:D4}"
                                : texture.Name);

                        try
                        {
                            byte[] data = Headerizer.Headerize(
                                texture, out string extension);

                            if (string.IsNullOrWhiteSpace(extension))
                                extension = ".bin";

                            string fileName = UniqueName(
                                $"{i:D4}_{name}{extension}", usedNames);

                            File.WriteAllBytes(
                                Path.Combine(textureDirectory, fileName), data);

                            succeeded++;
                        }
                        catch (Exception ex)
                        {
                            failed++;
                            Console.Error.WriteLine(
                                $"Texture failed: {work.RelativePath}, " +
                                $"index {i}: {ex.Message}");
                        }
                    }

                    item.Output = textureRelative;
                    item.EntriesExtracted = succeeded;
                    item.Status = failed == 0
                        ? "ExtractedTPF"
                        : "ExtractedTPFWithErrors";

                    report.ContainersExpanded++;
                    report.EntriesExtracted += succeeded;
                    report.Items.Add(item);

                    Console.WriteLine(
                        $"TPF: {work.RelativePath} -> " +
                        $"{succeeded}/{tpf.Textures.Count} textures");

                    // A partial texture export is recorded as a failure.
                    if (failed > 0)
                        report.Failures++;

                    continue;
                }

                // Unknown and ordinary leaf assets must not be discarded.
                string leaf = SafePath(output, work.RelativePath);
                Directory.CreateDirectory(Path.GetDirectoryName(leaf)!);

                if (!File.Exists(leaf))
                    File.WriteAllBytes(leaf, bytes);

                item.Output = work.RelativePath;
                item.OutputBytes = bytes.LongLength;
                item.Status = "PreservedLeaf";
                report.Items.Add(item);
            }
            catch (Exception ex)
            {
                item.Status = "Failed";
                item.Error = $"{ex.GetType().Name}: {ex.Message}";
                report.Failures++;
                report.Items.Add(item);

                Console.Error.WriteLine(
                    $"FAILED: {work.RelativePath}: {item.Error}");
            }
        }

        report.CompletedAtUtc = DateTimeOffset.UtcNow;

        string reportPath = Path.Combine(
            output, "recursive-extraction.json");

        File.WriteAllText(reportPath,
            JsonSerializer.Serialize(
                report, new JsonSerializerOptions { WriteIndented = true }));

        Console.WriteLine();
        Console.WriteLine("====== RECURSIVE EXTRACTION ======");
        Console.WriteLine($"Files visited      : {report.FilesVisited}");
        Console.WriteLine($"Containers expanded : {report.ContainersExpanded}");
        Console.WriteLine($"Entries extracted   : {report.EntriesExtracted}");
        Console.WriteLine($"Failures            : {report.Failures}");
        Console.WriteLine($"Report              : {reportPath}");

        return report.Failures == 0 ? 0 : 1;
    }

    private static bool Has(byte[] bytes, string signature) =>
        bytes.Length >= signature.Length &&
        Encoding.ASCII.GetString(bytes, 0, signature.Length) == signature;

    private static string ContainerDirectory(string relative)
    {
        string directory = Path.GetDirectoryName(relative) ?? "";
        string stem = SafeName(Path.GetFileNameWithoutExtension(relative));
        return Path.Combine(directory, stem);
    }

    private static string AddSuffix(string relative, string suffix) =>
        Path.Combine(
            Path.GetDirectoryName(relative) ?? "",
            Path.GetFileNameWithoutExtension(relative) + suffix +
            Path.GetExtension(relative));

    private static string SafeName(string name)
    {
        string leaf = name.Replace('\\', '/').Split('/').LastOrDefault() ?? "";

        foreach (char c in Path.GetInvalidFileNameChars()
                     .Concat(new[] { '<', '>', ':', '"', '|', '?', '*' }))
            leaf = leaf.Replace(c, '_');

        return leaf.Trim().TrimEnd('.');
    }

    private static string UniqueName(
        string name, HashSet<string> usedNames)
    {
        if (usedNames.Add(name))
            return name;

        string stem = Path.GetFileNameWithoutExtension(name);
        string ext = Path.GetExtension(name);
        int suffix = 1;
        string candidate;

        do
        {
            candidate = $"{stem}_{suffix++}{ext}";
        } while (!usedNames.Add(candidate));

        return candidate;
    }

    private static string SafePath(string root, string relative)
    {
        string fullRoot = Path.GetFullPath(root)
            .TrimEnd(Path.DirectorySeparatorChar) +
            Path.DirectorySeparatorChar;

        string full = Path.GetFullPath(Path.Combine(root, relative));

        if (!full.StartsWith(
                fullRoot, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "Entry path escaped the output directory.");

        return full;
    }

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
