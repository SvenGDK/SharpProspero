using SharpProspero.Prx;
using System;
using System.Buffers.Binary;
using Xunit;

namespace SharpProspero.Tests;

public sealed class ShaderInfoTests
{
    private const int HeaderOffset = 128;
    private const int HeaderSize = 192;

    [Theory]
    [InlineData(112, 160)]
    [InlineData(128, 176)]
    public void Read_ResolvesEachRegisterArrayRelativeToItsOwnPointerField(int contextStart, int shaderStart)
    {
        byte[] container = Container();
        Span<byte> header = container.AsSpan(HeaderOffset, HeaderSize);
        Pointer(header, 24, (ulong)(contextStart - 24), 2);
        Pointer(header, 32, (ulong)(shaderStart - 32), 2);
        Register(header, contextStart, 0x01C4, 0x11223344);
        Register(header, contextStart + 8, 0x008F, 0x55667788);
        Register(header, shaderStart, 0x0008, 0x99AABBCC);
        Register(header, shaderStart + 8, 0x0009, 0xDDEEFF00);

        ShaderInfo info = ShaderInfo.Read(container);

        Assert.True(info.IsValid);
        Assert.Equal(new[] {
            new ShaderRegisterWrite(0x01C4, 0x11223344),
            new ShaderRegisterWrite(0x008F, 0x55667788)
        }, info.ContextRegisters);
        Assert.Equal(new[] {
            new ShaderRegisterWrite(0x0008, 0x99AABBCC),
            new ShaderRegisterWrite(0x0009, 0xDDEEFF00)
        }, info.ShaderRegisters);
    }

    [Theory]
    [InlineData(0ul, 2)]
    [InlineData(80ul, 0)]
    [InlineData(0ul, 0)]
    public void Read_NullPointersOrZeroCountsProduceEmptyArrays(ulong relativeOffset, byte count)
    {
        byte[] container = Container();
        Span<byte> header = container.AsSpan(HeaderOffset, HeaderSize);
        Pointer(header, 24, relativeOffset, count);
        Pointer(header, 32, relativeOffset, count);

        ShaderInfo info = ShaderInfo.Read(container);

        Assert.Empty(info.ContextRegisters);
        Assert.Empty(info.ShaderRegisters);
    }

    [Theory]
    [InlineData(24, 185)]
    [InlineData(24, 192)]
    [InlineData(24, 1024)]
    [InlineData(32, 185)]
    [InlineData(32, 192)]
    [InlineData(32, 1024)]
    public void Read_DoesNotReadARecordBeyondTheHeader(int field, int start)
    {
        byte[] container = Container();
        Pointer(container.AsSpan(HeaderOffset, HeaderSize), field, (ulong)(start - field), 1);

        ShaderInfo info = ShaderInfo.Read(container);

        Assert.Empty(info.ContextRegisters);
        Assert.Empty(info.ShaderRegisters);
    }

    [Theory]
    [InlineData(24, ulong.MaxValue)]
    [InlineData(32, ulong.MaxValue)]
    [InlineData(24, 0x7FFFFFFFFFFFFFFFul)]
    [InlineData(32, 0x7FFFFFFFFFFFFFFFul)]
    public void Read_AnOversizedRelativeOffsetDoesNotOverflowIntoTheHeader(int field, ulong relativeOffset)
    {
        byte[] container = Container();
        Pointer(container.AsSpan(HeaderOffset, HeaderSize), field, relativeOffset, 1);

        ShaderInfo info = ShaderInfo.Read(container);

        Assert.Empty(info.ContextRegisters);
        Assert.Empty(info.ShaderRegisters);
    }

    [Theory]
    [InlineData(24, 1)]
    [InlineData(24, 2)]
    [InlineData(32, 1)]
    [InlineData(32, 2)]
    public void Read_KeepsTheFinalCompleteRecordButNotATruncatedSuccessor(int field, byte count)
    {
        byte[] container = Container();
        Span<byte> header = container.AsSpan(HeaderOffset, HeaderSize);
        Pointer(header, field, (ulong)(HeaderSize - 8 - field), count);
        Register(header, HeaderSize - 8, 0x0123, 0x89ABCDEF);

        ShaderInfo info = ShaderInfo.Read(container);
        var selected = field == 24 ? info.ContextRegisters : info.ShaderRegisters;
        var other = field == 24 ? info.ShaderRegisters : info.ContextRegisters;

        Assert.Equal(new ShaderRegisterWrite(0x0123, 0x89ABCDEF), Assert.Single(selected));
        Assert.Empty(other);
    }

    private static void Pointer(Span<byte> header, int field, ulong relativeOffset, byte count)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(header[field..], relativeOffset);
        header[field == 24 ? 91 : 92] = count;
    }

    private static void Register(Span<byte> header, int at, ushort offset, uint value)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(header[at..], offset);
        BinaryPrimitives.WriteUInt32LittleEndian(header[(at + 4)..], value);
    }

    // Minimal ELF64 fixture containing a string table and a synthetic shader header. No shader code,
    // copied SDK binary, device initialization or production reader is used to construct the records.
    private static byte[] Container()
    {
        const int sectionTable = HeaderOffset + HeaderSize;
        byte[] data = new byte[sectionTable + 3 * 64];
        BinaryPrimitives.WriteUInt32LittleEndian(data, 0x464C457F);
        data[4] = 2; // ELF64
        data[5] = 1; // little endian
        data[6] = 1; // ELF version
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x28), sectionTable);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x34), 64);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x3A), 64);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x3C), 3);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x3E), 1);
        ReadOnlySpan<byte> names = "\0.shstrtab\0.shader_header\0"u8;
        names.CopyTo(data.AsSpan(64));
        Section(data.AsSpan(sectionTable + 64, 64), 1, 3, 64, (ulong)names.Length);
        Section(data.AsSpan(sectionTable + 128, 64), 11, 1, HeaderOffset, HeaderSize);
        Span<byte> header = data.AsSpan(HeaderOffset, HeaderSize);
        BinaryPrimitives.WriteUInt32LittleEndian(header, 0x34333231);
        BinaryPrimitives.WriteUInt32LittleEndian(header[4..], 24);
        BinaryPrimitives.WriteUInt32LittleEndian(header[64..], HeaderSize);
        header[90] = 1; // pixel
        return data;
    }

    private static void Section(Span<byte> section, uint name, uint type, ulong offset, ulong size)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(section, name);
        BinaryPrimitives.WriteUInt32LittleEndian(section[4..], type);
        BinaryPrimitives.WriteUInt64LittleEndian(section[24..], offset);
        BinaryPrimitives.WriteUInt64LittleEndian(section[32..], size);
    }
}
