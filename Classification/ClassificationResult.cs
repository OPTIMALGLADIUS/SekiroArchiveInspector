namespace SekiroArchiveInspector.Classification;

public sealed class ClassificationResult
{
    public required string FilePath { get; init; }

    public required AssetFormat Format { get; init; }

    public required string DetectionMethod { get; init; }

    public required string HeaderHex { get; init; }

    public required string HeaderAscii { get; init; }

    public string Notes { get; init; } = "";
}
