// Divide the buffer size by 3 to determine chunk sizes
int chunkSize = Warhead.Length / 3;
int remainder = Warhead.Length % 3;

// Copy the first chunk
Marshal.Copy(Warhead, 0, ptr_local_section_addr, chunkSize);

// Copy the second chunk
Marshal.Copy(Warhead, chunkSize, IntPtr.Add(ptr_local_section_addr, chunkSize), chunkSize);

// Copy the third chunk, including any remainder bytes
Marshal.Copy(Warhead, 2 * chunkSize, IntPtr.Add(ptr_local_section_addr, 2 * chunkSize), chunkSize + remainder);
