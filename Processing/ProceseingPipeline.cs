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
