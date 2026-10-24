using System;
using System.Buffers.Binary;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using SoulsFormats;
using UXM;

internal static class Program
{
    private const string DefaultDictionaryPath =
        "../UXM-Selective-Unpack/UXM/res/SekiroDictionary.txt";

    private static int Main(string[] args)
    {
        if (args.Length > 0)
        {
            if (args[0].Equals("--extract", StringComparison.OrdinalIgnoreCase))
                return RunExtraction(args);

            if (args[0].Equals("--extract-tpf", StringComparison.OrdinalIgnoreCase))
                return RunTpfExtraction(args);
        }

        return RunMapping(args);
    }

    // ------------------------------------------------------------
    // Original TSV mapping mode
    // Usage:
    // dotnet run -- <DataN.bhd> [dictionary.txt]
    // ------------------------------------------------------------

    private static int RunMapping(string[] args)
    {
        if (args.Length < 1 || args.Length > 2)
        {
            PrintUsage();
            return 2;
        }

        string bhdPath = Path.GetFullPath(args[0]);

        string dictionaryPath = args.Length == 2
            ? Path.GetFullPath(args[1])
            : Path.GetFullPath(DefaultDictionaryPath);

        if (!File.Exists(bhdPath) || !File.Exists(dictionaryPath))
        {
            Console.Error.WriteLine("BHD or dictionary file not found.");
            Console.Error.WriteLine($"BHD: {bhdPath}");
            Console.Error.WriteLine($"Dictionary: {dictionaryPath}");
            return 2;
        }

        string archive = Path.GetFileNameWithoutExtension(bhdPath);

        if (!ArchiveKeys.SekiroKeys.TryGetValue(archive, out string key))
        {
            Console.Error.WriteLine(
                $"No Sekiro key found for archive '{archive}'.");
            return 2;
        }

        try
        {
            BHD5 bhd = LoadBhd(bhdPath, key);

            var dictionary = new ArchiveDictionary(
                File.ReadAllText(dictionaryPath),
                BHD5.Game.DarkSouls3);

            var entries = bhd.Buckets
                .SelectMany(bucket => bucket)
                .ToList();

            string outputPath = Path.Combine(
                Environment.CurrentDirectory,
                $"{archive}-mapped.tsv");

            int matched = 0;
            int unmatched = 0;

            using (var writer = new StreamWriter(outputPath))
            {
                writer.WriteLine(
                    "Hash\tPath\tOffset\tPaddedSize\tUnpaddedSize");

                foreach (var entry in entries)
                {
                    if (dictionary.GetPath(
                            entry.FileNameHash, out string path))
                    {
                        matched++;

                        writer.WriteLine(
                            $"0x{entry.FileNameHash:X8}\t{path}\t" +
                            $"{entry.FileOffset}\t" +
                            $"{entry.PaddedFileSize}\t" +
                            $"{entry.UnpaddedFileSize}");
                    }
                    else
                    {
                        unmatched++;
                    }
                }
            }

            Console.WriteLine($"Archive: {archive}");
            Console.WriteLine($"Total entries: {entries.Count:N0}");
            Console.WriteLine($"Matched paths: {matched:N0}");
            Console.WriteLine($"Unmatched hashes: {unmatched:N0}");
            Console.WriteLine($"Mapping report: {outputPath}");

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"{ex.GetType().Name}: {ex.Message}");

            return 1;
        }
    }

    // ------------------------------------------------------------
    // Existing BHD5 entry extraction + AES decryption
    //
    // Usage:
    // dotnet run -- --extract <DataN.bhd> <DataN.bdt>
    //                  <hash> <outputDir>
    // ------------------------------------------------------------

    private static int RunExtraction(string[] args)
    {
        if (args.Length != 5)
        {
            PrintUsage();
            return 2;
        }

        string bhdPath = Path.GetFullPath(args[1]);
        string bdtPath = Path.GetFullPath(args[2]);
        string hashText = args[3];
        string outputDir = Path.GetFullPath(args[4]);

        if (!File.Exists(bhdPath))
        {
            Console.Error.WriteLine($"BHD file not found: {bhdPath}");
            return 2;
        }

        if (!File.Exists(bdtPath))
        {
            Console.Error.WriteLine($"BDT file not found: {bdtPath}");
            return 2;
        }

        string archive = Path.GetFileNameWithoutExtension(bhdPath);

        if (!ArchiveKeys.SekiroKeys.TryGetValue(archive, out string key))
        {
            Console.Error.WriteLine(
                $"No Sekiro key found for archive '{archive}'.");
            return 2;
        }

        if (!TryParseHash(hashText, out ulong targetHash))
        {
            Console.Error.WriteLine($"Invalid hexadecimal hash: {hashText}");
            return 2;
        }

        try
        {
            BHD5 bhd = LoadBhd(bhdPath, key);

            var entry = bhd.Buckets
                .SelectMany(bucket => bucket)
                .FirstOrDefault(file => file.FileNameHash == targetHash);

            if (entry == null)
            {
                Console.Error.WriteLine(
                    $"Hash 0x{targetHash:X8} was not found in the BHD.");

                return 1;
            }

            Directory.CreateDirectory(outputDir);

            byte[] bytes;

            using (FileStream bdtStream = File.OpenRead(bdtPath))
            {
                // Reads the entry from its BDT offset and applies
                // AES decryption specified by the BHD metadata.
                bytes = entry.ReadFile(bdtStream);
            }

            string outputPath = Path.Combine(
                outputDir,
                $"0x{targetHash:X8}.decrypted.bin");

            File.WriteAllBytes(outputPath, bytes);

            string firstBytes = Convert.ToHexString(
                bytes.Take(Math.Min(bytes.Length, 32)).ToArray());

            var report = new
            {
                Archive = archive,
                Hash = $"0x{targetHash:X8}",
                BdtPath = bdtPath,
                FileOffset = entry.FileOffset,
                PaddedFileSize = entry.PaddedFileSize,
                UnpaddedFileSize = entry.UnpaddedFileSize,
                ActualOutputSize = bytes.Length,
                AesMetadataPresent = entry.AESKey != null,
                AesRangeCount = entry.AESKey?.Ranges.Count ?? 0,
                First32Bytes = firstBytes,
                OutputPath = outputPath
            };

            string reportPath = Path.Combine(
                outputDir,
                $"0x{targetHash:X8}.report.json");

            File.WriteAllText(
                reportPath,
                JsonSerializer.Serialize(
                    report,
                    new JsonSerializerOptions
                    {
                        WriteIndented = true
                    }));

            Console.WriteLine("Extraction completed.");
            Console.WriteLine($"Archive: {archive}");
            Console.WriteLine($"Hash: 0x{targetHash:X8}");
            Console.WriteLine($"Offset: {entry.FileOffset}");
            Console.WriteLine($"Padded size: {entry.PaddedFileSize}");
            Console.WriteLine($"Unpadded size: {entry.UnpaddedFileSize}");
            Console.WriteLine($"AES metadata present: {entry.AESKey != null}");
            Console.WriteLine($"AES ranges: {entry.AESKey?.Ranges.Count ?? 0}");
            Console.WriteLine($"Output size: {bytes.Length}");
            Console.WriteLine($"First 32 bytes: {firstBytes}");
            Console.WriteLine($"Output: {outputPath}");
            Console.WriteLine($"Report: {reportPath}");

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"{ex.GetType().Name}: {ex.Message}");

            return 1;
        }
    }

    // ------------------------------------------------------------
    // DCX decompression + TPF texture extraction
    //
    // Usage:
    // dotnet run -- --extract-tpf <decrypted.bin> <outputDir>
    // ------------------------------------------------------------

    private static int RunTpfExtraction(string[] args)
    {
        if (args.Length != 3)
        {
            PrintUsage();
            return 2;
        }

        string inputPath = Path.GetFullPath(args[1]);
        string outputDir = Path.GetFullPath(args[2]);

        if (!File.Exists(inputPath))
        {
            Console.Error.WriteLine(
                $"Input file not found: {inputPath}");
            return 2;
        }

        try
        {
            Directory.CreateDirectory(outputDir);

            byte[] dcxBytes = File.ReadAllBytes(inputPath);

            Console.WriteLine($"Input: {inputPath}");
            Console.WriteLine($"Input size: {dcxBytes.Length:N0} bytes");

            if (!DCX.Is(dcxBytes))
            {
                Console.Error.WriteLine(
                    "Input does not appear to be a DCX file.");

                return 1;
            }

            // Actual SoulsFormatsNEXT API from the supplied DCX.cs.
            byte[] tpfBytes = DCX.Decompress(
                dcxBytes,
                out DCX.CompressionInfo compression);

            Console.WriteLine(
                $"DCX compression type: {compression.Type}");

            Console.WriteLine(
                $"Decompressed size: {tpfBytes.Length:N0} bytes");

            // Verify the decompressed file is a TPF.
            if (tpfBytes.Length < 4 ||
                Encoding.ASCII.GetString(tpfBytes, 0, 4) != "TPF\0")
            {
                string unexpectedPath = Path.Combine(
                    outputDir,
                    "decompressed.bin");

                File.WriteAllBytes(unexpectedPath, tpfBytes);

                Console.Error.WriteLine(
                    "DCX decompression completed, but the output " +
                    "does not begin with the TPF signature.");

                Console.Error.WriteLine(
                    $"Output saved for inspection: {unexpectedPath}");

                Console.Error.WriteLine(
                    $"First 16 bytes: {Convert.ToHexString(tpfBytes.Take(16).ToArray())}");

                return 1;
            }

            string tpfPath = Path.Combine(
                outputDir,
                "common_body.tpf");

            File.WriteAllBytes(tpfPath, tpfBytes);

            // Actual SoulsFormatsNEXT TPF reader.
            TPF tpf = TPF.Read(tpfBytes);

            string textureDir = Path.Combine(
                outputDir,
                "textures");

            Directory.CreateDirectory(textureDir);

            var textureReports =
                new System.Collections.Generic.List<object>();

            int index = 0;

            foreach (TPF.Texture texture in tpf.Textures)
            {
                string safeName = MakeSafeFileName(texture.Name);

                // Headerize converts supported texture payloads into a
                // standard DDS file, including rebuilding platform-specific
                // layouts where Headerizer supports them. Some payloads are
                // already DDS/GNF/XTX; Headerizer identifies those too.
                byte[] outputBytes;
                string extension;
                bool headerized;
                string headerizeError = null;

                try
                {
                    outputBytes = Headerizer.Headerize(
                        texture,
                        out extension);

                    headerized = true;
                }
                catch (Exception ex)
                {
                    // Do not abort the entire TPF because one texture is
                    // unsupported or malformed. Preserve its original bytes.
                    outputBytes = texture.Bytes;
                    extension = ".bin";
                    headerized = false;

                    headerizeError =
                        $"{ex.GetType().Name}: {ex.Message}";
                }

                // Parse the DDS header directly instead of relying on
                // texture.Header, which may be null for these textures.
                DdsInfo ddsInfo = null;

                if (extension.Equals(
                        ".dds",
                        StringComparison.OrdinalIgnoreCase))
                {
                    ddsInfo = ParseDds(outputBytes);
                }

                string fileName =
                    $"{index:D4}_{safeName}{extension}";

                string texturePath = Path.Combine(
                    textureDir,
                    fileName);

                File.WriteAllBytes(texturePath, outputBytes);

                textureReports.Add(new
                {
                    Index = index,
                    Name = texture.Name,
                    File = fileName,

                    OriginalByteLength = texture.Bytes.Length,
                    OutputByteLength = outputBytes.Length,

                    OutputFormat =
                        extension.TrimStart('.').ToUpperInvariant(),

                    Headerized = headerized,
                    HeaderizeError = headerizeError,

                    Platform = texture.Platform.ToString(),
                    Format = texture.Format,
                    Type = texture.Type.ToString(),
                    Mipmaps = texture.Mipmaps,
                    Flags1 = texture.Flags1,

                    // Metadata parsed from the generated DDS file.
                    Width = ddsInfo?.Width,
                    Height = ddsInfo?.Height,
                    MipMapCount = ddsInfo?.MipMapCount,
                    FourCC = ddsInfo?.FourCC,
                    DXGIFormat = ddsInfo?.DxgiFormat,
                    FormatName = ddsInfo?.FormatName,

                    DdsHeaderValid = ddsInfo?.IsValid ?? false,
                    DdsValidationMessage =
                        ddsInfo?.ValidationMessage,

                    // Preserve the previous SoulsFormats header fields
                    // as supplemental information for comparison.
                    SourceHeaderWidth = texture.Header?.Width,
                    SourceHeaderHeight = texture.Header?.Height,
                    SourceHeaderTextureCount =
                        texture.Header?.TextureCount,
                    SourceHeaderDXGIFormat =
                        texture.Header?.DXGIFormat
                });

                Console.WriteLine(
                    $"[{index:D4}] {texture.Name} | " +
                    $"Format={texture.Format} | " +
                    $"Type={texture.Type} | " +
                    $"Mipmaps={texture.Mipmaps} | " +
                    $"Output={extension} | " +
                    $"Bytes={outputBytes.Length:N0}" +
                    (headerized
                        ? ""
                        : " | Headerize failed; saved raw bytes"));

                if (!headerized)
                {
                    Console.Error.WriteLine(
                        $"  Headerize error: {headerizeError}");
                }
                else if (ddsInfo != null)
                {
                    Console.WriteLine(
                        $"  DDS: {ddsInfo.Width}x{ddsInfo.Height} | " +
                        $"Mips={ddsInfo.MipMapCount} | " +
                        $"Format={ddsInfo.FormatName} | " +
                        $"Valid={ddsInfo.IsValid}");
                }

                index++;
            }

            var report = new
            {
                InputFile = inputPath,
                InputSize = dcxBytes.Length,

                CompressionType = compression.Type.ToString(),

                DecompressedTpfPath = tpfPath,
                DecompressedTpfSize = tpfBytes.Length,

                TpfPlatform = tpf.Platform.ToString(),
                TpfEncoding = tpf.Encoding,
                TpfFlag2 = tpf.Flag2,

                TextureCount = tpf.Textures.Count,
                TextureOutputDirectory = textureDir,

                Textures = textureReports
            };

            string reportPath = Path.Combine(
                outputDir,
                "tpf_report.json");

            File.WriteAllText(
                reportPath,
                JsonSerializer.Serialize(
                    report,
                    new JsonSerializerOptions
                    {
                        WriteIndented = true
                    }));

            Console.WriteLine();
            Console.WriteLine("TPF extraction completed.");
            Console.WriteLine($"TPF: {tpfPath}");
            Console.WriteLine($"Texture count: {tpf.Textures.Count}");
            Console.WriteLine($"Textures: {textureDir}");
            Console.WriteLine($"Report: {reportPath}");

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"{ex.GetType().Name}: {ex.Message}");

            Console.Error.WriteLine(ex.StackTrace);

            return 1;
        }
    }

    // ------------------------------------------------------------
    // DDS header parsing
    //
    // Standard DDS layout:
    //   0-3     Magic "DDS "
    //   4-127   DDS_HEADER
    //   128+    Optional DDS_HEADER_DXT10
    //
    // This validates the header structure and extracts metadata.
    // It does not fully decode or validate the texture payload.
    // ------------------------------------------------------------

    private sealed class DdsInfo
    {
        public bool IsValid { get; set; }

        public string ValidationMessage { get; set; } = "";

        public int? Width { get; set; }

        public int? Height { get; set; }

        public int? MipMapCount { get; set; }

        public string FourCC { get; set; }

        public uint? DxgiFormat { get; set; }

        public string FormatName { get; set; }
    }

    private static DdsInfo ParseDds(byte[] data)
    {
        var info = new DdsInfo();

        if (data == null || data.Length < 128)
        {
            info.ValidationMessage =
                "DDS data is shorter than 128 bytes.";

            return info;
        }

        // DDS magic.
        if (data[0] != (byte)'D' ||
            data[1] != (byte)'D' ||
            data[2] != (byte)'S' ||
            data[3] != (byte)' ')
        {
            info.ValidationMessage =
                "DDS magic is missing.";

            return info;
        }

        uint headerSize =
            BinaryPrimitives.ReadUInt32LittleEndian(
                data.AsSpan(4, 4));

        if (headerSize != 124)
        {
            info.ValidationMessage =
                $"Unexpected DDS_HEADER size: {headerSize}.";

            return info;
        }

        uint height =
            BinaryPrimitives.ReadUInt32LittleEndian(
                data.AsSpan(12, 4));

        uint width =
            BinaryPrimitives.ReadUInt32LittleEndian(
                data.AsSpan(16, 4));

        uint mipMapCount =
            BinaryPrimitives.ReadUInt32LittleEndian(
                data.AsSpan(28, 4));

        uint pixelFormatSize =
            BinaryPrimitives.ReadUInt32LittleEndian(
                data.AsSpan(76, 4));

        uint pixelFormatFlags =
            BinaryPrimitives.ReadUInt32LittleEndian(
                data.AsSpan(80, 4));

        uint fourCCValue =
            BinaryPrimitives.ReadUInt32LittleEndian(
                data.AsSpan(84, 4));

        if (pixelFormatSize != 32)
        {
            info.ValidationMessage =
                $"Unexpected DDS_PIXELFORMAT size: {pixelFormatSize}.";

            return info;
        }

        if (width > int.MaxValue || height > int.MaxValue)
        {
            info.ValidationMessage =
                "DDS dimensions exceed supported integer range.";

            return info;
        }

        info.Width = (int)width;
        info.Height = (int)height;

        info.MipMapCount =
            (int)Math.Max(1u, mipMapCount);

        // DDPF_FOURCC = 0x4.
        if ((pixelFormatFlags & 0x4) != 0)
        {
            info.FourCC = new string(new[]
            {
                (char)(fourCCValue & 0xFF),
                (char)((fourCCValue >> 8) & 0xFF),
                (char)((fourCCValue >> 16) & 0xFF),
                (char)((fourCCValue >> 24) & 0xFF)
            });

            if (info.FourCC == "DX10")
            {
                // DDS_HEADER_DXT10 is 20 bytes and begins at offset 128.
                if (data.Length < 148)
                {
                    info.ValidationMessage =
                        "DDS uses DX10 format but its extended header is incomplete.";

                    return info;
                }

                uint dxgiFormat =
                    BinaryPrimitives.ReadUInt32LittleEndian(
                        data.AsSpan(128, 4));

                info.DxgiFormat = dxgiFormat;
                info.FormatName = GetDxgiFormatName(dxgiFormat);
            }
            else
            {
                info.FormatName = info.FourCC switch
                {
                    "DXT1" => "BC1",
                    "DXT2" => "BC2 premultiplied",
                    "DXT3" => "BC2",
                    "DXT4" => "BC3 premultiplied",
                    "DXT5" => "BC3",
                    "ATI1" => "BC4",
                    "BC4U" => "BC4 UNORM",
                    "BC4S" => "BC4 SNORM",
                    "ATI2" => "BC5",
                    "BC5U" => "BC5 UNORM",
                    "BC5S" => "BC5 SNORM",
                    _ => $"FourCC {info.FourCC}"
                };
            }
        }
        else
        {
            info.FormatName = "Uncompressed DDS";
        }

        info.IsValid =
            width > 0 &&
            height > 0;

        info.ValidationMessage = info.IsValid
            ? "DDS header is structurally valid."
            : "DDS dimensions are invalid.";

        return info;
    }

    private static string GetDxgiFormatName(uint format)
    {
        return format switch
        {
            2  => "R32G32B32A32_FLOAT",
            10 => "R16G16B16A16_FLOAT",
            11 => "R16G16B16A16_UNORM",
            28 => "R8G8B8A8_UNORM",
            29 => "R8G8B8A8_UNORM_SRGB",
            49 => "R8G8_UNORM",
            61 => "R8_UNORM",

            71 => "BC1_UNORM",
            72 => "BC1_UNORM_SRGB",
            74 => "BC2_UNORM",
            75 => "BC2_UNORM_SRGB",
            77 => "BC3_UNORM",
            78 => "BC3_UNORM_SRGB",
            80 => "BC4_UNORM",
            81 => "BC4_SNORM",
            83 => "BC5_UNORM",
            84 => "BC5_SNORM",

            87 => "B8G8R8A8_UNORM",
            88 => "B8G8R8X8_UNORM",

            95 => "BC6H_UF16",
            96 => "BC6H_SF16",
            98 => "BC7_UNORM",
            99 => "BC7_UNORM_SRGB",

            _ => $"Unknown DXGI format ({format})"
        };
    }

    // ------------------------------------------------------------
    // Shared BHD loading logic
    // ------------------------------------------------------------

    private static BHD5 LoadBhd(string bhdPath, string key)
    {
        byte[] magic = new byte[4];

        using (FileStream file = File.OpenRead(bhdPath))
        {
            if (file.Read(magic, 0, magic.Length) != magic.Length)
            {
                throw new InvalidDataException(
                    "BHD header is too short.");
            }
        }

        bool encrypted =
            Encoding.ASCII.GetString(magic) != "BHD5";

        if (encrypted)
        {
            using var decrypted =
                CryptographyUtility.DecryptRsa(bhdPath, key);

            return BHD5.Read(
                decrypted,
                BHD5.Game.DarkSouls3);
        }

        return BHD5.Read(
            bhdPath,
            BHD5.Game.DarkSouls3);
    }

    // ------------------------------------------------------------
    // Hash parsing
    // Accepts:
    // F92A250B
    // 0xF92A250B
    // ------------------------------------------------------------

    private static bool TryParseHash(
        string hashText,
        out ulong hash)
    {
        string normalized = hashText.StartsWith(
            "0x", StringComparison.OrdinalIgnoreCase)
                ? hashText[2..]
                : hashText;

        return ulong.TryParse(
            normalized,
            NumberStyles.HexNumber,
            CultureInfo.InvariantCulture,
            out hash);
    }

    // ------------------------------------------------------------
    // Make output filenames safe for Windows/Linux runners.
    // ------------------------------------------------------------

    private static string MakeSafeFileName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return "unnamed";

        char[] invalidChars = Path.GetInvalidFileNameChars();

        string safe = new string(
            name.Select(c =>
                invalidChars.Contains(c) || c == '/' || c == '\\'
                    ? '_'
                    : c)
            .ToArray());

        return string.IsNullOrWhiteSpace(safe)
            ? "unnamed"
            : safe;
    }

    // ------------------------------------------------------------
    // Usage
    // ------------------------------------------------------------

    private static void PrintUsage()
    {
        Console.WriteLine("Sekiro Archive Inspector");
        Console.WriteLine();

        Console.WriteLine("TSV mapping:");
        Console.WriteLine(
            "  dotnet run -- <DataN.bhd> [dictionary.txt]");
        Console.WriteLine();

        Console.WriteLine("Targeted BHD5 entry extraction:");
        Console.WriteLine(
            "  dotnet run -- --extract <DataN.bhd> " +
            "<DataN.bdt> <hash> <outputDir>");
        Console.WriteLine();

        Console.WriteLine("DCX -> TPF -> texture extraction:");
        Console.WriteLine(
            "  dotnet run -- --extract-tpf <decrypted.bin> <outputDir>");
        Console.WriteLine();

        Console.WriteLine("Examples:");
        Console.WriteLine(
            "  dotnet run -- --extract Data2.bhd Data2.bdt " +
            "0xF92A250B output");
        Console.WriteLine();

        Console.WriteLine(
            "  dotnet run -- --extract-tpf " +
            "output/0xF92A250B.decrypted.bin output/common_body");
    }
}
