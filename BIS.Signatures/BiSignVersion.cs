using System;

namespace BIS.Signatures
{
    /// <summary>
    /// Represents version of the BIS signing algorithm.
    /// </summary>
    public enum BiSignVersion : Int32
    {
        /// <summary>
        /// The legacy version used to sign ArmA and ArmA 2 addons.
        /// </summary>
        V2 = 2,
        /// <summary>
        /// The version used to sign ArmA 3 and DayZ addons.
        /// </summary>
        V3 = 3
    }
}
