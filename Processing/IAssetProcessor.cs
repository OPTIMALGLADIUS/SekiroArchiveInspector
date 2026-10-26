using SekiroArchiveInspector.Classification;

namespace SekiroArchiveInspector.Processing;

public interface IAssetProcessor
{
    AssetFormat SupportedFormat { get; }

    Task ProcessAsync(
        string inputPath,
        string outputDirectory,
        CancellationToken cancellationToken = default);
}
