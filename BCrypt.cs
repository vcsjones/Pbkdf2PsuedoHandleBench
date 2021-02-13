using System;
using System.Runtime.InteropServices;

namespace Pbkdf2PsuedoHandleBench
{
    internal partial class BCrypt
    {
        [DllImport(nameof(BCrypt), CharSet = CharSet.Unicode)]
        internal static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, BCryptOpenAlgorithmProviderFlags dwFlags);

        [Flags]
        internal enum BCryptOpenAlgorithmProviderFlags : int
        {
            None = 0x00000000,
            BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008,
        }

        [DllImport(nameof(BCrypt), CharSet = CharSet.Unicode)]
        internal static extern unsafe int BCryptDeriveKeyPBKDF2(
            IntPtr hPrf,
            byte* pbPassword,
            int cbPassword,
            byte* pbSalt,
            int cbSalt,
            ulong cIterations,
            byte* pbDerivedKey,
            int cbDerivedKey,
            int dwFlags);

        public enum BCryptAlgPseudoHandle : uint
        {
            BCRYPT_MD5_ALG_HANDLE = 0x00000021,
            BCRYPT_SHA1_ALG_HANDLE = 0x00000031,
            BCRYPT_SHA256_ALG_HANDLE = 0x00000041,
            BCRYPT_SHA384_ALG_HANDLE = 0x00000051,
            BCRYPT_SHA512_ALG_HANDLE = 0x00000061,

            BCRYPT_HMAC_MD5_ALG_HANDLE = 0x00000091,
            BCRYPT_HMAC_SHA1_ALG_HANDLE = 0x000000A1,
            BCRYPT_HMAC_SHA256_ALG_HANDLE = 0x000000B1,
            BCRYPT_HMAC_SHA384_ALG_HANDLE = 0x000000C1,
            BCRYPT_HMAC_SHA512_ALG_HANDLE = 0x000000D1,
        }
    }
}