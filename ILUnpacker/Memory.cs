using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace ILUnpacker
{
    internal static class Memory
    {
        [DllImport("ILUnpackerNative-x86.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern void ILUnpacker_SetHook86(IntPtr from, IntPtr to);

        [DllImport("ILUnpackerNative-x64.dll", CallingConvention = CallingConvention.FastCall)]
        public static extern void ILUnpacker_SetHook64(IntPtr from, IntPtr to);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllToLoad);

        internal static void Hook(MethodBase from, MethodBase to)
        {
            LoadLibrary(IntPtr.Size == 4 ? "ILUnpackerNative-x86.dll" : "ILUnpackerNative-x64.dll");

            var intPtr = GetAddress(from);
            var intPtr2 = GetAddress(to);

            if (IntPtr.Size == 4)
            {
                ILUnpacker_SetHook86(intPtr, intPtr2);
            }
            else
            {
                ILUnpacker_SetHook64(intPtr, intPtr2);
            }
        }

        public static IntPtr GetAddress(MethodBase methodBase)
        {
            RuntimeHelpers.PrepareMethod(methodBase.MethodHandle);
            return methodBase.MethodHandle.GetFunctionPointer();
        }
    }
}