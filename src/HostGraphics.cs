using System.Runtime.InteropServices;

namespace CompatPrep;

internal static class HostGraphics
{
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("d3d12.dll", ExactSpelling = true)]
    private static extern int D3D12CreateDevice(IntPtr adapter, int minimumLevel, in Guid iid, out IntPtr device);

    public static object Probe()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var iid = new Guid("189819F1-1DB6-4B57-BE54-1821339B85F7");
        var results = new Dictionary<string,string>();
        foreach (var (name, level) in new[]{("11_0",0xb000),("12_0",0xc000),("12_1",0xc100),("12_2",0xc200)})
        {
            int hr = D3D12CreateDevice(IntPtr.Zero,level,in iid,out var handle);
            try { results[name] = hr >= 0 && handle != IntPtr.Zero ? "device-created" : $"HRESULT 0x{hr:X8}"; }
            finally { if (handle != IntPtr.Zero) Marshal.Release(handle); }
        }
        return new { adapter="Windows default", api="Desktop Direct3D 12", featureLevels=results };
    }
}
