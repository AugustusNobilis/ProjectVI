using System.Text.RegularExpressions;

namespace CompatPrep;

internal record SdkLookup(string? Version,string Status,int FilesRead,int Skipped,
    Dictionary<string,List<string>> Mentions)
{
    public static SdkLookup Check(IEnumerable<string> symbols)
    {
        var names=symbols.Distinct(StringComparer.Ordinal).ToArray();
        var hits=new Dictionary<string,List<string>>(StringComparer.Ordinal);
        if(names.Length==0) return new(null,"nothing-to-check",0,0,hits);
        if(names.Length>128) return new(null,"too-many-symbols-for-optional-header-search",0,0,hits);
        foreach(var n in names.Where(n=>Regex.IsMatch(n,@"\A[A-Za-z_]\w{0,255}\z",RegexOptions.CultureInvariant))) hits[n]=new();
        if(hits.Count==0)return new(null,"no-C-identifiers",0,0,hits);
        int read=0,skipped=0;
        string? version=null;
        try
        {
            string sdk=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),"Windows Kits","10","Include");
            if(!Directory.Exists(sdk))return new(null,"SDK-not-installed",0,0,hits);
            var latest=Directory.EnumerateDirectories(sdk)
                .Where(p=>VersionNumber(Path.GetFileName(p))!=null && Directory.Exists(Path.Combine(p,"um")))
                .OrderByDescending(p=>VersionNumber(Path.GetFileName(p))).FirstOrDefault();
            if(latest==null)return new(null,"no-headers",0,0,hits);
            version=Path.GetFileName(latest);
            var matcher=new Regex(@"(?<![a-zA-Z_0-9])(?:"+string.Join("|",hits.Keys.Select(Regex.Escape))+@")(?![a-zA-Z_0-9])",
                RegexOptions.CultureInvariant|RegexOptions.Compiled,TimeSpan.FromSeconds(2));
            var files=new PackageFiles(latest);
            var errors=new List<string>();
            foreach(string p in files.Enumerate(errors))
            {
                if(Path.GetExtension(p).ToLowerInvariant() is not (".h" or ".hpp" or ".inl" or ".idl"))continue;
                try
                {
                    using var stream=files.Open(p);
                    if(stream.Length>16*1024*1024){skipped++;continue;}
                    using var reader=new StreamReader(stream,detectEncodingFromByteOrderMarks:true);
                    string body=reader.ReadToEnd();
                    var seen=new HashSet<string>(StringComparer.Ordinal);
                    foreach(Match m in matcher.Matches(body))
                        if(seen.Add(m.Value)) hits[m.Value].Add(p);
                    read++;
                }
                catch(Exception e) when(e is IOException or UnauthorizedAccessException or RegexMatchTimeoutException)
                { skipped++; }
            }
            return new(version,"searched",read,skipped+errors.Count,hits);
        }
        catch(Exception e) when(e is IOException or UnauthorizedAccessException)
        {return new(version,"SDK-inaccessible",read,skipped,hits);}
    }
    private static System.Version? VersionNumber(string s)=>System.Version.TryParse(s,out var v)?v:null;
}
