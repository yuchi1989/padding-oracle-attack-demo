from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64encode, b64decode
from Crypto.Hash import HMAC

class PaddingOracleAttack():
	def __init__(self):
		pass

	def AES_encrypt(self, plaintext, key):
		self.key = key
		data = self.pad(plaintext.encode())
		iv = Random.new().read(AES.block_size);
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return (iv + cipher.encrypt(data))
		
	def AES_decrypt(self, ciphertext, key):	
		self.key = key	
		iv = ciphertext[:16]
		ciphertext= ciphertext[16:]
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		data = cipher.decrypt(ciphertext)
		if not self.check_padding(data):
			return b""
		return self.unpad(data).decode()
	def pad(self, data):
		length = 16 - (len(data) % 16)
		data += (chr(length)*length).encode("ascii")
		return data
	def unpad(self, data):
		
		data = data[:-(data[-1])]
		return data

	def check_padding(self, data):
		if data[-1] > AES.block_size or data[-1] <= 0:
			#print(data[-1])
			return False
		if data[-(data[-1]):] != ((chr(data[-1])*data[-1]).encode("ascii")):
			return False
		return True

	def padding_oracle(self, ciphertext):
		iv = ciphertext[:16]
		ciphertext= ciphertext[16:]
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		data = cipher.decrypt(ciphertext)
		if not self.check_padding(data):
			return False
		else:
			return True

	def hack(self, ciphertext):
		block = len(ciphertext)//16
		print(block)
		dtext = b''
		for i in range(block-1):
			dblock = b''
			for j in range(16):
				
				temp = bytearray(ciphertext[:16*(i+2)])
				for l in range(j):
					
					temp[16*(i+1)-(l+1)] = temp[16*(i+1)-(l+1)] ^ (j+1) ^ dblock[-(l+1)]
				tempbyte = temp[16*(i+1)-(j+1)]
				hit = 0
				for k in range(255):
					if k==j+1:
						continue
					temp[16*(i+1)-(j+1)] = tempbyte ^ (j+1) ^ k
					r = self.padding_oracle(bytes(temp))
					if r != False:
						dblock = chr(k).encode("ascii") + dblock
						hit = 1
						break
				if hit == 0:
					dblock = chr(j+1).encode("ascii") + dblock
				print (chr(dblock[0]), end=" ")
			dtext = dtext + dblock
			print("\n%s" % dtext.decode())
		dtext = dtext[:-(dtext[-1])]
		print("%s" % dtext.decode())




if __name__== "__main__":

	print (AES.block_size)
	key = "a"*32
	#plaintext = "hello world hello world hello world hello world"
	plaintext = "abcdefghijklmnopqrstuvwxyz"
	print(plaintext.encode())
	key=key[:32]
	cipher = PaddingOracleAttack()
	ciphertext = cipher.AES_encrypt(plaintext, key)
	plaintext = cipher.AES_decrypt(ciphertext, key)
	print ("%s" % plaintext)

	
	block = len(ciphertext)//16
	print(block)
	dtext = b''
	for i in range(block-1):
		dblock = b''
		for j in range(16):
			#print("%d,%d" % (i,j))
			temp = bytearray(ciphertext[:16*(i+2)])
			for l in range(j):
				#print("%d, %d" % (j,l))
				#print(dblock[-(l+1)])
				temp[16*(i+1)-(l+1)] = temp[16*(i+1)-(l+1)] ^ (j+1) ^ dblock[-(l+1)]
			tempbyte = temp[16*(i+1)-(j+1)]
			hit = 0
			for k in range(255):
				if k==j+1:
					continue
				temp[16*(i+1)-(j+1)] = tempbyte ^ (j+1) ^ k
				r = cipher.padding_oracle(bytes(temp))
				if r != False:
					dblock = chr(k).encode("ascii") + dblock
					hit = 1
					break
			if hit == 0:
				dblock = chr(j+1).encode("ascii") + dblock
			print (chr(dblock[0]), end=" ")
		dtext = dtext + dblock
		print("\n%s" % dtext.decode())
	dtext = dtext[:-(dtext[-1])]
	print("%s" % dtext.decode())


