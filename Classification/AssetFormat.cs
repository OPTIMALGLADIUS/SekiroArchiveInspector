namespace SekiroArchiveInspector.Classification;

public enum AssetFormat
{
    Unknown,

    // Compression and archive formats
    DCX,
    BHD,
    BDT,
    BND,
    Binder,

    // Texture formats
    TPF,
    DDS,

    // Model formats
    FLVER,
    FLVER2,

    // Animation and physics formats
    TAE,
    HKX,

    // Other formats
    FFX,
    FMG,
    FSB,

    Binary
}
