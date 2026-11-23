using System.Reflection.PortableExecutable;
using System.Text;

namespace CompatPrep;

// Match only exact contracts in the local v6 API-set namespace, including importer-specific
// aliases. A missing entry stays unresolved instead of guessing by the name/version prefix.
internal sealed class ApiSchema
{
    private readonly Dictionary<string,Dictionary<string,string>> entries = new(StringComparer.OrdinalIgnoreCase);
    public string? Resolve(string contract,string consumer)
    {
        if(!entries.TryGetValue(Path.GetFileNameWithoutExtension(contract),out var hosts)) return null;
        return hosts.GetValueOrDefault(Path.GetFileName(consumer)) ?? hosts.GetValueOrDefault("");
    }

    public IEnumerable<(string Contract,string Host)> Nearby(string library,string consumer)
    {
        // Only vary the last numeric revision. A similarly named contract is a lead,
        // never an exact resolution of an import.
        string name=Path.GetFileNameWithoutExtension(library);
        int split=name.LastIndexOf('-');
        if(split<0 || !uint.TryParse(name.AsSpan(split+1),out _)) yield break;
        string prefix=name[..(split+1)];
        foreach(string candidate in entries.Keys.Order(StringComparer.OrdinalIgnoreCase))
        {
            if(!candidate.StartsWith(prefix,StringComparison.OrdinalIgnoreCase) ||
                candidate.Equals(name,StringComparison.OrdinalIgnoreCase) ||
                !uint.TryParse(candidate.AsSpan(prefix.Length),out _)) continue;
            string? host=Resolve(candidate+".dll",consumer);
            if(host!=null) yield return (candidate+".dll",host);
        }
    }
    internal static ApiSchema Load(List<string> limits)
    {
        try
        {
            using var f=new PackageFiles(Environment.SystemDirectory).Open("apisetschema.dll");
            using var pe=new PEReader(f);
            var section=pe.PEHeaders.SectionHeaders.Single(x=>x.Name==".apiset");
            if(section.SizeOfRawData<28 || section.SizeOfRawData>16*1024*1024) throw new InvalidDataException();
            byte[] data=new byte[section.SizeOfRawData];
            f.Position=section.PointerToRawData;f.ReadExactly(data);
            return Parse(data);
        }
        catch(Exception e) when(e is IOException or UnauthorizedAccessException or BadImageFormatException or
                                    InvalidOperationException or OverflowException or ArgumentException or InvalidDataException)
        { limits.Add("System32 API-set schema ["+e.GetType().Name+"]");return new(); }
    }
    internal static ApiSchema Parse(byte[] data)
    {
        var result=new ApiSchema();
        int end=data.Length;
        int I(int p)
        {
            if(p<0 || p>end-4) throw new InvalidDataException();
            return checked((int)BitConverter.ToUInt32(data,p));
        }
        string Text(int p,int size)
        {
            if(p<0 || size<0 || size%2!=0 || size>2048 || p>end-size) throw new InvalidDataException();
            return Encoding.Unicode.GetString(data,p,size);
        }
        if(I(0)!=6 || I(4)>end || I(4)<28) throw new InvalidDataException("Unsupported API-set schema.");
        end=I(4); int count=I(12), start=I(16);
        if(count>65536 || start>end-count*24) throw new InvalidDataException();
        for(int i=0;i<count;i++)
        {
            int row=start+i*24;
            string name=Text(I(row+4),I(row+8));
            int values=I(row+16), n=I(row+20);
            if(n>4096 || values>end-n*20) throw new InvalidDataException();
            var hosts=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            for(int j=0;j<n;j++)
            {
                int v=values+j*20;
                string alias=Text(I(v+4),I(v+8)), host=Text(I(v+12),I(v+16));
                if(host.Length>0) hosts[alias]=host;
            }
            result.entries.Add(name,hosts);
        }
        return result;
    }
}
