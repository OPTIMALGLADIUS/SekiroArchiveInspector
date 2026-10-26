using SekiroArchiveInspector.Archive;
using SekiroArchiveInspector.Configuration;
using SekiroArchiveInspector.Extraction;
using SekiroArchiveInspector.Reporting;
using SekiroArchiveInspector.Utilities;

internal static class Program
{
    private const string DefaultDictionaryPath =
        "../UXM-Selective-Unpack/UXM/res/SekiroDictionary.txt";

    private static async Task<int> Main(string[] args)
    {
        try
        {
            OodleConfiguration.Configure();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"Oodle configuration failed: {ex.Message}");

            return 1;
        }

        if (args.Length == 0)
        {
            PrintUsage();
            return 2;
        }

        try
        {
            switch (args[0].ToLowerInvariant())
            {
                case "--extract":
                    return ArchiveExtractor.RunSingle(args);

                case "--extract-tpf":
                    return TpfExtractionService.Run(args);

                case "--extract-all":
                    return ArchiveExtractor.RunAll(args);

                case "--classify-all":
                    ClassificationReport.ScanDirectory(
                        args[1],
                        args[2]);

                    return 0;

                default:
                    // Preserve the original TSV mapping mode.
                    return ArchiveMapper.Run(args);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"{ex.GetType().Name}: {ex.Message}");

            ExceptionUtility.PrintExceptionDetails(ex);

            return 1;
        }
    }

    private static async Task<int> RunProcessAll(
        string[] args)
    {
        if (args.Length != 3)
        {
            PrintUsage();
            return 2;
        }

        string inputDirectory =
            Path.GetFullPath(args[1]);

        string outputDirectory =
            Path.GetFullPath(args[2]);

        var pipeline = new ProcessingPipeline(
        [
            new DcxProcessor(),
            new TpfProcessor(),
            new BinderProcessor()
        ]);

        await pipeline.ProcessDirectoryAsync(
            inputDirectory,
            outputDirectory);

        return 0;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Sekiro Archive Inspector");
        Console.WriteLine();

        Console.WriteLine(
            "Mapping: -- <DataN.bhd> [dictionary.txt]");

        Console.WriteLine(
            "Extract entry: --extract <DataN.bhd> " +
            "<DataN.bdt> <hash> <outputDir>");

        Console.WriteLine(
            "Extract all: --extract-all <DataN.bhd> " +
            "<DataN.bdt> <outputDir>");

        Console.WriteLine(
            "Extract TPF: --extract-tpf " +
            "<decrypted.bin> <outputDir>");

        Console.WriteLine(
            "Classify: --classify-all " +
            "<inputDir> <output.csv>");

        Console.WriteLine(
            "Process: --process-all " +
            "<inputDir> <outputDir>");
    }
}
