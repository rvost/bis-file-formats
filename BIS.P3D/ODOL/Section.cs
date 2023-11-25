using System.Collections.Generic;
using BIS.Core.Streams;

namespace BIS.P3D.ODOL
{
	public class Section
	{
		internal Section(BinaryReaderEx input, int version)
		{
            isShortFaceIndices = (version < 69);

            FaceLowerIndex = input.ReadInt32();
			FaceUpperIndex = input.ReadInt32();
			MinBoneIndex = input.ReadInt32();
			BonesCount = input.ReadInt32();
			Unused = input.ReadUInt32();
			TextureIndex = input.ReadInt16();
			Special = input.ReadUInt32();
			MaterialIndex = input.ReadInt32();
			if (MaterialIndex == -1)
			{
				Material = input.ReadAsciiz();
			}
			if (version >= 36)
			{
				AreaOverTex = input.ReadArray(i => i.ReadSingle());
				if (version >= 67)
				{
					Flag67 = input.ReadInt32();
					if (Flag67 >= 1)
					{
						Unused67 = input.ReadArrayBase(i => input.ReadSingle(), 11);
					}
				}
			}
			else
			{
				AreaOverTex = new[] { input.ReadSingle() };
			}
		}

        private readonly bool isShortFaceIndices;

        public int FaceLowerIndex { get; }
		public int FaceUpperIndex { get; }
		public int MinBoneIndex { get; }
		public int BonesCount { get; }
		public uint Unused { get; }
		public short TextureIndex { get; }
		public uint Special { get; }
		public int MaterialIndex { get; }
		public string Material { get; set; }
		public float[] AreaOverTex { get; }
		public int Flag67 { get; }
		public float[] Unused67 { get; }

		internal void Write(BinaryWriterEx output, int version)
		{
			output.Write(FaceLowerIndex);
			output.Write(FaceUpperIndex);
			output.Write(MinBoneIndex);
			output.Write(BonesCount);
			output.Write(Unused);
			output.Write(TextureIndex);
			output.Write(Special);
			output.Write(MaterialIndex);
			if (MaterialIndex == -1)
			{
				output.WriteAsciiz(Material);
			}
			if (version >= 36)
			{
				output.WriteArray(AreaOverTex);
				if (version >= 67)
				{
					output.Write(Flag67);
					if (Flag67 >= 1)
					{
						output.WriteArrayBase(Unused67, (o,v) => o.Write(v));
					}
				}
			}
			else
			{
				output.Write(AreaOverTex[0]);
			}
		}

        public IEnumerable<Polygon> GetFaces(Polygon[] faces)
        {
            uint position = 0u;
            uint sizeOfFace3 = isShortFaceIndices ? 8u : 16u;
            uint padOfFace4 = isShortFaceIndices ? 2u : 4u;

			for (var index = 0; index < faces.Length && position < FaceUpperIndex; ++index)
			{
				if (position >= FaceLowerIndex && position < FaceUpperIndex)
				{
					yield return faces[index];
				}
				position += sizeOfFace3;
				if (faces[index].VertexIndices.Length == 4)
				{
					position += padOfFace4;
				}
			}
        }
    }
}