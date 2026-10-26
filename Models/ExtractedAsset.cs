public sealed class ExtractedAsset
{
    public required string FilePath { get; init; }

    public required string SourceArchive { get; init; }

    public required string SourceEntryHash { get; init; }

    public string? ParentAsset { get; init; }

    public AssetFormat Format { get; set; }

    public int ProcessingDepth { get; set; }
}
