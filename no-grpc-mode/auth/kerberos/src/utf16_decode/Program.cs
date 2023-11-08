// Windows seems to use UTF-16.
// For Linux use, UTF-16 strings have to be
// translated to UTF-8.
//
class EncodeToUTF8 {
    public static void Main() {
        const int inputBufferSize = 1024;
        // Reading beyond 1K is not needed for gMSA purposes

        byte[] utf16Bytes = new byte[inputBufferSize];

        System.IO.Stream inputStream = System.Console.OpenStandardInput();
        inputStream.Read(utf16Bytes, 0, inputBufferSize);

        System.Text.Encoding utf8 = System.Text.Encoding.UTF8;
        System.Text.Encoding utf16 = System.Text.Encoding.Unicode;

        byte[] utf8Bytes = System.Text.Encoding.Convert(System.Text.Encoding.Unicode,
                                System.Text.Encoding.UTF8, utf16Bytes);
        System.IO.Stream outputStream = System.Console.OpenStandardOutput();
        outputStream.Write(utf8Bytes);
    }
}
