using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using System.Text;

namespace CompatPrep;

internal record Import(string Module, string Symbol, bool Delayed);
internal record ExportTable(Dictionary<string,string?> Values);
internal record ImageInfo(string Role, string Architecture, string Subsystem, bool HasEntry, List<Import> Imports);

internal sealed class PeFile : IDisposable
{
    private readonly Stream stream;
    private readonly PEReader reader;
    private readonly PEHeader header;
    private readonly bool wide;
    private readonly byte[] buffer = new byte[8];

    public PeFile(Stream stream)
    {
        this.stream = stream;
        reader = new PEReader(stream, PEStreamOptions.LeaveOpen);
        try
        {
            header = reader.PEHeaders.PEHeader ?? throw new BadImageFormatException("Missing PE header.");
            wide = header.Magic == PEMagic.PE32Plus;
        }
        catch { reader.Dispose(); throw; }
    }
    public void Dispose() => reader.Dispose();

    private long Offset(uint rva, int size)
    {
        if (size < 0) throw new BadImageFormatException();
        if ((ulong)rva + (uint)size <= (uint)header.SizeOfHeaders &&
            (long)rva + size <= stream.Length) return rva;
        foreach (var s in reader.PEHeaders.SectionHeaders)
        {
            long delta = (long)rva - (uint)s.VirtualAddress;
            long file = (uint)s.PointerToRawData + delta;
            if (delta >= 0 && delta + size <= (uint)s.SizeOfRawData && file >= 0 && file <= stream.Length - size)
                return file;
        }
        throw new BadImageFormatException("RVA is outside section data.");
    }
    private ulong Number(uint rva, int size)
    {
        stream.Position = Offset(rva,size);
        stream.ReadExactly(buffer,0,size);
        return size switch { 2 => BinaryPrimitives.ReadUInt16LittleEndian(buffer),
            4 => BinaryPrimitives.ReadUInt32LittleEndian(buffer), 8 => BinaryPrimitives.ReadUInt64LittleEndian(buffer),
            _ => throw new ArgumentOutOfRangeException(nameof(size)) };
    }
    private uint U32(uint rva) => (uint)Number(rva,4);
    private string Str(uint rva)
    {
        var bytes = new List<byte>();
        for (int i = 0; i < 1024; i++)
        {
            stream.Position = Offset(checked(rva+(uint)i),1);
            int value = stream.ReadByte();
            if (value == 0 && bytes.Count > 0) return Encoding.ASCII.GetString(bytes.ToArray());
            if (value < 32 || value > 126) throw new BadImageFormatException("Invalid PE name.");
            bytes.Add((byte)value);
        }
        throw new BadImageFormatException("PE name is too long.");
    }

    public ImageInfo Inspect()
    {
        var list = new List<Import>();
        Imports(header.ImportTableDirectory, false, list);
        Imports(header.DelayImportTableDirectory, true, list);
        var coff = reader.PEHeaders.CoffHeader;
        string role = (int)header.Subsystem == 17 ? "xbox-code-catalog" :
            coff.Characteristics.HasFlag(Characteristics.Dll) ? "dll" : "executable";
        return new(role,coff.Machine.ToString(),header.Subsystem.ToString(),header.AddressOfEntryPoint != 0,list);
    }

    private void Imports(DirectoryEntry dir, bool delay, List<Import> imports)
    {
        if (dir.RelativeVirtualAddress == 0 || dir.Size == 0) return;
        uint rva = (uint)dir.RelativeVirtualAddress;
        int size = delay ? 32 : 20;
        int limit = Math.Min(dir.Size/size,4096);
        for (int i=0; i<limit; i++)
        {
            uint d = checked(rva+(uint)(size*i));
            uint name = U32(d+(delay ? 4u : 12u));
            uint table = U32(d+(delay ? 16u : 0u));
            if (name == 0 && table == 0) return;
            uint attr = delay ? U32(d) : 1;
            uint AsRva(uint v) => v == 0 || (attr & 1) != 0 ? v :
                checked((uint)((ulong)v - header.ImageBase));
            var module = Str(AsRva(name));
            if (table == 0) table = U32(d+(delay ? 12u : 16u));
            if (table == 0) throw new BadImageFormatException("Import has no address table.");
            ReadThunks(module,AsRva(table),delay,attr,imports);
        }
        throw new BadImageFormatException("Unterminated import array.");
    }

    private void ReadThunks(string module, uint table, bool delay, uint attr, List<Import> imports)
    {
        int size = wide ? 8 : 4;
        ulong bit = wide ? 1UL<<63 : 1UL<<31;
        for (int j=0;j<65536 && imports.Count<250000;j++)
        {
            ulong t = Number(checked(table+(uint)(size*j)),size);
            if (t == 0) return;
            string symbol = (t & bit) != 0 ? "#" + (t & 0xffff) :
                Str(checked((uint)(((attr & 1) == 0 ? t-header.ImageBase : t)+2)));
            imports.Add(new(module,symbol,delay));
        }
        throw new BadImageFormatException("Import symbol limit exceeded.");
    }

    public ExportTable Exports()
    {
        var result = new Dictionary<string,string?>(StringComparer.Ordinal);
        var dir = header.ExportTableDirectory;
        if (dir.RelativeVirtualAddress == 0 || dir.Size == 0) return new(result);
        uint r = (uint)dir.RelativeVirtualAddress, baseOrd=U32(r+16), count=U32(r+20), names=U32(r+24);
        uint funcs=U32(r+28), ptrs=U32(r+32), ords=U32(r+36);
        if (count>100000 || names>100000) throw new BadImageFormatException();
        for (uint i=0;i<count;i++)
        {
            uint value=U32(checked(funcs+i*4));
            if (value == 0) continue;
            result["#"+checked(baseOrd+i)] = value>=r && (ulong)value < (ulong)r+(uint)dir.Size ? Str(value) : null;
        }
        for (uint i=0;i<names;i++)
        {
            uint index=(uint)Number(checked(ords+i*2),2);
            if (index >= count) throw new BadImageFormatException();
            if (result.TryGetValue("#"+checked(baseOrd+index),out var forward))
                result[Str(U32(checked(ptrs+i*4)))] = forward;
        }
        return new(result);
    }
}
