namespace SekiroArchiveInspector.Utilities;

public static class FileNameUtility
{
    public static string MakeSafeFileName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return "unnamed";

        char[] invalidChars =
            Path.GetInvalidFileNameChars();

        string safe = new string(
            name.Select(c =>
                invalidChars.Contains(c) ||
                c == '/' ||
                c == '\\'
                    ? '_'
                    : c)
            .ToArray());

        return string.IsNullOrWhiteSpace(safe)
            ? "unnamed"
            : safe;
    }
}
