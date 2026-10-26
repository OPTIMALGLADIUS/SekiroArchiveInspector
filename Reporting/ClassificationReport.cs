using System.Text;
using SekiroArchiveInspector.Classification;

namespace SekiroArchiveInspector.Reporting;

public static class ClassificationReport
{
    public static void ScanDirectory(
        string inputDirectory,
        string outputCsv)
    {
        if (!Directory.Exists(inputDirectory))
        {
            throw new DirectoryNotFoundException(
                $"Input directory not found: {inputDirectory}");
        }

        string[] files = Directory.GetFiles(
            inputDirectory,
            "*.bin",
            SearchOption.AllDirectories);

        List<ClassificationResult> results = files
            .Select(AssetClassifier.Classify)
            .ToList();

        using StreamWriter writer = new(outputCsv, false, Encoding.UTF8);

        writer.WriteLine(
            "FilePath,Format,DetectionMethod,HeaderHex,HeaderAscii,Notes");

        foreach (ClassificationResult result in results)
        {
            writer.WriteLine(string.Join(",",
                Csv(result.FilePath),
                Csv(result.Format.ToString()),
                Csv(result.DetectionMethod),
                Csv(result.HeaderHex),
                Csv(result.HeaderAscii),
                Csv(result.Notes)));
        }

        Console.WriteLine($"Scanned {results.Count} files.");

        foreach (var group in results.GroupBy(r => r.Format))
        {
            Console.WriteLine($"{group.Key}: {group.Count()}");
        }

        Console.WriteLine($"Report written to: {outputCsv}");
    }

    private static string Csv(string value)
    {
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }
}
