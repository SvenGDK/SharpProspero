// SharpProspero.Prx - module inspection and stub generation.
// Copyright (C) 2026 SvenGDK

// Reads a compiled shader binary for inspection: its kind, version, sizes, and the register writes it
// carries. A shader binary is an ELF container with two sections - a header block describing the program
// and a block of microcode. This reads the header fields and the register arrays the header points at,
// without preparing or running the shader.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace SharpProspero.Prx;

/// <summary>One register write a shader program carries: a register offset and the value to write.</summary>
public readonly record struct ShaderRegisterWrite(ushort Offset, uint Value);

/// <summary>The inspectable contents of a compiled shader binary.</summary>
public readonly record struct ShaderInfo(
    uint Magic, uint Version, byte Kind, uint DeclaredHeaderSize, uint DeclaredCodeSize, int CodeSectionSize,
    IReadOnlyList<ShaderRegisterWrite> ContextRegisters, IReadOnlyList<ShaderRegisterWrite> ShaderRegisters)
{
    /// <summary>The magic a valid shader-binary header block starts with.</summary>
    public const uint HeaderMagic = 0x34333231;

    /// <summary>Whether the header magic is the expected value.</summary>
    public bool IsValid => Magic == HeaderMagic;

    /// <summary>A readable name for the part of the pipeline the program runs at.</summary>
    public string KindName => Kind switch
    {
        0 => "compute",
        1 => "pixel",
        2 => "geometry",
        3 => "hull",
        4 => "geometry-front",
        5 => "hull-front",
        6 => "geometry-back",
        7 => "hull-back",
        8 => "function",
        _ => $"0x{Kind:X2}",
    };

    /// <summary>Reads the shader binary from its ELF container.</summary>
    /// <exception cref="PrxFormatException">The container is not a valid shader binary.</exception>
    public static ShaderInfo Read(byte[] container)
    {
        ArgumentNullException.ThrowIfNull(container);
        if (container.Length < 64 || BinaryPrimitives.ReadUInt32LittleEndian(container) != 0x464C457F)
            throw new PrxFormatException("File is not a shader-binary container.");

        ulong shoff = BinaryPrimitives.ReadUInt64LittleEndian(container.AsSpan(0x28));
        ushort shentsize = BinaryPrimitives.ReadUInt16LittleEndian(container.AsSpan(0x3A));
        ushort shnum = BinaryPrimitives.ReadUInt16LittleEndian(container.AsSpan(0x3C));
        ushort shstrndx = BinaryPrimitives.ReadUInt16LittleEndian(container.AsSpan(0x3E));
        if (shoff == 0 || shnum == 0 || shstrndx >= shnum)
            throw new PrxFormatException("Shader-binary container has no section table.");

        long strRec = (long)shoff + (long)shstrndx * shentsize;
        if (strRec < 0 || strRec + 40 > container.Length)
            throw new PrxFormatException("Shader-binary section table is out of range.");
        long strOff = (long)BinaryPrimitives.ReadUInt64LittleEndian(container.AsSpan((int)strRec + 24));

        byte[]? header = null;
        int codeSize = 0;
        for (int i = 0; i < shnum; i++)
        {
            long rec = (long)shoff + (long)i * shentsize;
            if (rec < 0 || rec + 40 > container.Length)
                break;
            uint nameIndex = BinaryPrimitives.ReadUInt32LittleEndian(container.AsSpan((int)rec));
            long off = (long)BinaryPrimitives.ReadUInt64LittleEndian(container.AsSpan((int)rec + 24));
            long size = (long)BinaryPrimitives.ReadUInt64LittleEndian(container.AsSpan((int)rec + 32));
            string name = ReadString(container, strOff + nameIndex);
            if (off < 0 || size < 0 || off + size > container.Length)
                continue;
            if (name == ".shader_header")
                header = container[(int)off..(int)(off + size)];
            else if (name == ".shader_text")
                codeSize = (int)size;
        }

        if (header is null)
            throw new PrxFormatException("Shader-binary container has no header section.");
        if (header.Length < 96)
            throw new PrxFormatException("Shader-binary header block is too short.");

        // Pointer offsets are relative to their own fields, not to the start of the header.
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(header);
        uint version = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(4));
        ulong cxOff = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(24));
        ulong shOff = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(32));
        uint headerSize = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(64));
        uint shaderSize = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(68));
        byte kind = header[90];
        int numCx = header[91];
        int numSh = header[92];

        return new ShaderInfo(
            magic, version, kind, headerSize, shaderSize, codeSize,
            ReadRegisters(header, 24, cxOff, numCx),
            ReadRegisters(header, 32, shOff, numSh));
    }

    // A register array stored in the header: each entry is a two-byte offset then a four-byte value, at a
    // four-byte boundary (eight bytes total). The array's pointer is relative to its own field.
    private static List<ShaderRegisterWrite> ReadRegisters(
        byte[] header, int pointerFieldOffset, ulong relativeOffset, int count)
    {
        if (count <= 0 || relativeOffset == 0)
            return [];
        // Bound before adding or converting so malformed offsets cannot wrap into the header.
        if (relativeOffset > (ulong)(header.Length - pointerFieldOffset))
            return [];
        long arrayOffset = pointerFieldOffset + (long)relativeOffset;
        var writes = new List<ShaderRegisterWrite>(count);
        for (int i = 0; i < count; i++)
        {
            long entry = (long)arrayOffset + (long)i * 8;
            if (entry < 0 || entry + 8 > header.Length)
                break;
            ushort offset = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan((int)entry));
            uint value = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan((int)entry + 4));
            writes.Add(new ShaderRegisterWrite(offset, value));
        }
        return writes;
    }

    private static string ReadString(byte[] data, long at)
    {
        if (at < 0 || at >= data.Length)
            return "";
        long end = at;
        while (end < data.Length && data[(int)end] != 0)
            end++;
        return System.Text.Encoding.ASCII.GetString(data, (int)at, (int)(end - at));
    }
}
