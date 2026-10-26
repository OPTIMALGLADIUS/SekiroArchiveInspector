using System;
using System.IO;
using System.Linq;
using UXM;

namespace SekiroArchiveInspector.Configuration;

public static class OodleConfiguration
{
    public static void Configure()
    {
        string baseDirectory = AppContext.BaseDirectory;

        string[] candidateDirectories =
        {
            baseDirectory,
            Path.Combine(baseDirectory, "native"),
            Path.Combine(
                baseDirectory,
                "runtimes",
                "win-x64",
                "native"),
            Environment.CurrentDirectory
        };

        string? environmentPath =
            Environment.GetEnvironmentVariable("OODLE_PATH");

        if (!string.IsNullOrWhiteSpace(environmentPath))
        {
            candidateDirectories = candidateDirectories
                .Prepend(environmentPath)
                .ToArray();
        }

        foreach (string directory in candidateDirectories)
        {
            if (!Directory.Exists(directory))
                continue;

            string fullPath = Path.GetFullPath(directory);

            if (!Oodle.SearchPaths.Contains(
                    fullPath,
                    StringComparer.OrdinalIgnoreCase))
            {
                Oodle.SearchPaths.Add(fullPath);
            }
        }

        Console.WriteLine("Configured Oodle search paths:");

        foreach (string path in Oodle.SearchPaths)
        {
            Console.WriteLine($"  {path}");

            foreach (string dllName in new[]
            {
                "oo2core_9_win64.dll",
                "oo2core_8_win64.dll",
                "oo2core_6_win64.dll"
            })
            {
                string dllPath = Path.Combine(path, dllName);

                if (File.Exists(dllPath))
                    Console.WriteLine($"    Found: {dllName}");
            }
        }
    }
}
