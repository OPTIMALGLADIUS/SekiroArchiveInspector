using SekiroArchiveInspector.Classification;

namespace SekiroArchiveInspector.Processing;

public sealed class ProcessingPipeline
{
    private readonly Dictionary<AssetFormat, IAssetProcessor> _processors;

    public ProcessingPipeline(
        IEnumerable<IAssetProcessor> processors)
    {
        _processors = processors.ToDictionary(
            processor => processor.SupportedFormat);
    }

    public async Task ProcessDirectoryAsync(
        string inputDirectory,
        string outputDirectory,
        CancellationToken cancellationToken = default)
    {
        if (!Directory.Exists(inputDirectory))
        {
            throw new DirectoryNotFoundException(
                $"Input directory not found: {inputDirectory}");
        }

        Directory.CreateDirectory(outputDirectory);

        string[] files = Directory.GetFiles(
            inputDirectory,
            "*",
            SearchOption.AllDirectories);

        Console.WriteLine(
            $"Found {files.Length} files to process.");

        foreach (string file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                await ProcessAsync(
                    file,
                    outputDirectory,
                    cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(
                    $"Failed to process {file}: {ex.Message}");
            }
        }
    }

    public async Task ProcessAsync(
        string inputPath,
        string outputDirectory,
        CancellationToken cancellationToken = default)
    {
        ClassificationResult result =
            AssetClassifier.Classify(inputPath);

        if (!_processors.TryGetValue(
                result.Format,
                out IAssetProcessor? processor))
        {
            Console.WriteLine(
                $"No processor registered for {result.Format}: {inputPath}");

            return;
        }

        await processor.ProcessAsync(
            inputPath,
            outputDirectory,
            cancellationToken);
    }
}
