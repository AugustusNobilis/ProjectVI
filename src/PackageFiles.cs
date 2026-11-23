using System.Buffers;
using System.Security.Cryptography;

namespace CompatPrep;

internal sealed class PackageFiles
{
    public string Root { get; }
    private readonly HashSet<string> exclusions = new(StringComparer.OrdinalIgnoreCase);
    private const int Skip = (int)(FileAttributes.ReparsePoint | FileAttributes.Offline) | 0x440000;

    public PackageFiles(string root, params string[] excludedPaths)
    {
        Root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        if (!Directory.Exists(Root) || ((int)File.GetAttributes(Root) & Skip) != 0)
            throw new IOException("A local directory without redirection is required.");
        foreach (var path in excludedPaths) exclusions.Add(Path.GetFullPath(path));
    }

    public IEnumerable<string> Enumerate(List<string> skipped)
    {
        var pending = new Stack<string>();
        pending.Push(Root);
        while (pending.TryPop(out var current))
        {
            string[] entries;
            try { entries = Directory.GetFileSystemEntries(current); }
            catch (Exception e) when (e is UnauthorizedAccessException or IOException)
            { skipped.Add(Path.GetRelativePath(Root, current)); continue; }
            foreach (var p in entries.Order(StringComparer.OrdinalIgnoreCase))
            {
                if (exclusions.Contains(p)) continue;
                FileAttributes attr;
                try { attr = File.GetAttributes(p); }
                catch (Exception e) when (e is UnauthorizedAccessException or IOException)
                { skipped.Add(Path.GetRelativePath(Root, p)); continue; }
                string rel = Path.GetRelativePath(Root, p);
                if (((int)attr & Skip) != 0) { skipped.Add(rel); continue; }
                if ((attr & FileAttributes.Directory) != 0) pending.Push(p);
                else yield return rel;
            }
        }
    }

    // Reparse points and cloud placeholders are deliberately outside this local package view.
    public FileStream Open(string relative)
    {
        if (Path.IsPathRooted(relative) || relative.IndexOf(':') >= 0)
            throw new ArgumentException("Specify a path relative to the package root.");
        var parts = relative.Replace('\\', '/').Split('/');
        var path = Root;
        foreach (var part in parts)
        {
            if (part is "" or "." or ".." || part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
                part.EndsWith(' ') || part.EndsWith('.') ||
                System.Text.RegularExpressions.Regex.IsMatch(part, @"^(CON(IN\$|OUT\$)?|NUL|AUX|PRN|COM[0-9¹²³]|LPT[0-9¹²³])(\.|$)",
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                throw new ArgumentException("Invalid path component.");
            path = Path.Combine(path, part);
            if (exclusions.Contains(path) || ((int)File.GetAttributes(path) & Skip) != 0)
                throw new IOException("This entry is excluded from the local package view.");
        }
        return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
    }

    public static string RangeHash(Stream stream, long offset, long count)
    {
        if (offset < 0 || count < 0 || offset > stream.Length || count > stream.Length - offset)
            throw new ArgumentOutOfRangeException(nameof(count), "The range extends beyond the file.");
        stream.Position = offset;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        try
        {
            while (count > 0)
            {
                int read = stream.Read(buffer, 0, (int)Math.Min(count, buffer.Length));
                if (read == 0) throw new EndOfStreamException();
                hash.AppendData(buffer, 0, read);
                count -= read;
            }
            return Convert.ToHexStringLower(hash.GetHashAndReset());
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
    }
}
