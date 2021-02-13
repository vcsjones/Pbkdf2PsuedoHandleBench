using System;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace Pbkdf2PsuedoHandleBench
{
    public class Pbkdf2Bench
    {
        public byte[] _salt, _password;

        [Params(100000)]
        public int iterations;

        public IntPtr _hashHandle;
        

        [GlobalSetup]
        public void GlobalSetup()
        {
            _password = new byte[32];
            _salt = new byte[32];
            RandomNumberGenerator.Fill(_password);
            RandomNumberGenerator.Fill(_salt);
            BCrypt.BCryptOpenAlgorithmProvider(out _hashHandle, "SHA512", null, BCrypt.BCryptOpenAlgorithmProviderFlags.BCRYPT_ALG_HANDLE_HMAC_FLAG);
        }

        [Benchmark]
        public unsafe void Handle()
        {
            Span<byte> destination = stackalloc byte[32];
            fixed (byte* pPassword = _password)
            fixed (byte* pSalt = _salt)
            fixed (byte* pDestination = destination)
            {
                BCrypt.BCryptDeriveKeyPBKDF2(_hashHandle, pPassword, _password.Length, pSalt, _salt.Length, 
                    (ulong)iterations, pDestination, destination.Length, 0);
            }
        }

        [Benchmark]
        public unsafe void PseudoHandle()
        {
            Span<byte> destination = stackalloc byte[32];
            fixed (byte* pPassword = _password)
            fixed (byte* pSalt = _salt)
            fixed (byte* pDestination = destination)
            {
                BCrypt.BCryptDeriveKeyPBKDF2((IntPtr)BCrypt.BCryptAlgPseudoHandle.BCRYPT_HMAC_SHA512_ALG_HANDLE, pPassword, _password.Length, pSalt, _salt.Length, 
                    (ulong)iterations, pDestination, destination.Length, 0);
            }
        }

        [Benchmark]
        public void GetBytes()
        {
            Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(_password, _salt, iterations, HashAlgorithmName.SHA512);
            _ = pbkdf2.GetBytes(32);
        }
    }
}