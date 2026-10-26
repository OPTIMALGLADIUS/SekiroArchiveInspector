namespace SekiroArchiveInspector.Textures;

public sealed class DdsInfo
{
    public bool IsValid { get; set; }

    public string ValidationMessage { get; set; } = "";

    public int? Width { get; set; }

    public int? Height { get; set; }

    public int? MipMapCount { get; set; }

    public string? FourCC { get; set; }

    public uint? DxgiFormat { get; set; }

    public string? FormatName { get; set; }
}
