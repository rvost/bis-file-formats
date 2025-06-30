using System;
using System.Linq;
using System.Numerics;
using BIS.Core;
using BIS.Core.Streams;

namespace BIS.P3D.ODOL
{
	public sealed class UVSet
	{
        private readonly bool isDiscretized;

        internal UVSet(BinaryReaderEx input, int version)
		{
            isDiscretized = false;
            if (version >= 45u)
			{
                isDiscretized = true;
                MinU = input.ReadSingle();
				MinV = input.ReadSingle();
				MaxU = input.ReadSingle();
				MaxV = input.ReadSingle();
			}
			NVertices = input.ReadUInt32();
			DefaultFill = input.ReadBoolean();
			var num = (version >= 45u) ? 4u : 8u;
			if (DefaultFill)
			{
				DefaultValue = input.ReadBytes((int)num);
			}
			else
			{
				UvData = input.ReadCompressedTracked(NVertices * num);
			}
		}

		public uint NVertices { get; }
		public TrackedArray<byte> UvData { get; }
		public byte[] DefaultValue { get; }
		public bool DefaultFill { get; }
		public float MinU { get; }
		public float MinV { get; }
		public float MaxU { get; }
		public float MaxV { get; }

		internal void Write(BinaryWriterEx output, int version)
		{
			if (version >= 45u)
			{
				output.Write(MinU);
				output.Write(MinV);
				output.Write(MaxU);
				output.Write(MaxV);
			}
			output.Write(NVertices);
			output.Write(DefaultFill);
			var num = (version >= 45u) ? 4u : 8u;
			if (DefaultFill)
			{
				output.Write(DefaultValue);
			}
			else
			{
				output.WriteCompressed(UvData);
			}
		}

        public Vector2[] GetUV()
        {
            double deltaU = 1.0;
            double deltaV = 1.0;
            if (isDiscretized)
            {
                deltaU = (double)(MaxU - MinU);
                deltaV = (double)(MaxV - MinV);
            }
            if (DefaultFill)
            {
                Vector2 value;
                if (isDiscretized)
                {
                    value.X = Scale(BitConverter.ToInt16(DefaultValue, 0), deltaU, MinU);
                    value.Y = Scale(BitConverter.ToInt16(DefaultValue, 2), deltaV, MinV);
                }
                else
                {
                    value.X = BitConverter.ToSingle(DefaultValue, 0);
                    value.Y = BitConverter.ToSingle(DefaultValue, 4);
                }
                return Enumerable.Repeat(value, (int)NVertices).ToArray();
            }

            var uvData = UvData.ToArray();
            var result = new Vector2[NVertices];
            for (var pos = 0;  pos < NVertices; pos++)
            {
                if (isDiscretized)
                {
                    result[pos].X = Scale(BitConverter.ToInt16(uvData, pos * 4), deltaU, MinU);
                    result[pos].Y = Scale(BitConverter.ToInt16(uvData, pos * 4 + 2), deltaV, MinV);
                }
                else
                {
                    result[pos].X = BitConverter.ToSingle(uvData, pos * 8);
                    result[pos].Y =  BitConverter.ToSingle(uvData, pos * 8 + 4);
                }
            }
            return result;
        }

        private float Scale(short value, double scale, float min)
        {
            return (float)(1.52587890625E-05 * (value + short.MaxValue) * scale) + min; // 2 ^ -16
        }
    }
}