#include <windows.h>
#include <d3d12.h>
#include <cstdio>
#include <wrl/client.h>
using Microsoft::WRL::ComPtr;

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2 || !SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)) return 2;
    HMODULE bridge = LoadLibraryExW(argv[1], nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!bridge) return 3;
    const auto serialize = reinterpret_cast<decltype(&D3D12SerializeVersionedRootSignature)>(
        GetProcAddress(bridge, "D3D12SerializeVersionedRootSignature"));
    const auto deserialize = reinterpret_cast<decltype(&D3D12CreateRootSignatureDeserializer)>(
        GetProcAddress(bridge, "D3D12CreateRootSignatureDeserializer"));
    if (!serialize || !deserialize) return 4;
    D3D12_ROOT_PARAMETER parameter{};
    parameter.ParameterType = D3D12_ROOT_PARAMETER_TYPE_32BIT_CONSTANTS;
    parameter.Constants = {3, 2, 4};
    parameter.ShaderVisibility = D3D12_SHADER_VISIBILITY_VERTEX;
    D3D12_VERSIONED_ROOT_SIGNATURE_DESC description{};
    description.Version = D3D_ROOT_SIGNATURE_VERSION_1_0;
    description.Desc_1_0.NumParameters = 1;
    description.Desc_1_0.pParameters = &parameter;
    ComPtr<ID3DBlob> blob, error;
    HRESULT hr = serialize(&description, blob.GetAddressOf(), error.GetAddressOf());
    if (FAILED(hr) || !blob || blob->GetBufferSize() == 0) return 5;
    ComPtr<ID3D12RootSignatureDeserializer> parsed;
    hr = deserialize(blob->GetBufferPointer(), blob->GetBufferSize(), IID_PPV_ARGS(parsed.GetAddressOf()));
    if (FAILED(hr) || !parsed) return 6;
    const auto* result = parsed->GetRootSignatureDesc();
    if (!result || result->NumParameters != 1 || !result->pParameters) return 7;
    const auto& p = result->pParameters[0];
    if (p.ParameterType != parameter.ParameterType || p.ShaderVisibility != parameter.ShaderVisibility ||
        p.Constants.ShaderRegister != 3 || p.Constants.RegisterSpace != 2 || p.Constants.Num32BitValues != 4)
        return 8;
    D3D12_VERSIONED_ROOT_SIGNATURE_DESC invalid{};
    invalid.Version = static_cast<D3D_ROOT_SIGNATURE_VERSION>(0);
    ComPtr<ID3DBlob> invalidBlob, diagnostic;
    if (SUCCEEDED(serialize(&invalid, invalidBlob.GetAddressOf(), diagnostic.GetAddressOf()))) return 9;
    std::puts("DESKTOP_ROOT_SIGNATURE_ROUNDTRIP_PASS");
    return 0;
}
