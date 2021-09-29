# -*- coding: utf-8 -*-
"""
Created on Thu Dec 31 17:35:11 2020

@author: diego
"""

"""
SCRIPT sencillo para encriptar y desencriptar mis contraseñas
"""


# FILE MANAGER

# Opens file selected in open_file button and breturns binded data
def read_file(file_name, direction=True):
    if direction:
        with open(file_name, "r") as rfile:
            return rfile.read()
    else:
        with open(file_name, "rb") as rfile:
            global iv
            iv = rfile.read(16)
            return rfile.read()

# Creamos un nuevo archivo, con nombre file_name y contenido message
def delete_file(file_name):
    os.remove(file_name)


def create(file_name, message, direction=True):
    if direction:
        with open(file_name, "wb") as wfile:
            wfile.write(cipher.iv)
            wfile.write(message)
            wfile.close()
    else:
        with open(file_name, "w") as wfile:
            wfile.write(message)
            wfile.close() 


# ENCRYPTION ALGORITHM
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64, os

# SECURITY TIMER
import time

def generate_secret_key_for_AES_cipher():
	# AES key length must be either 16, 24, or 32 bytes long. We select 32.
	# We know have our 32 bit key assigned to the "key" variable
	key = get_random_bytes(32)
	# encode this secret key for storing safely in database
	encoded_secret_key = base64.b64encode(key)
	return encoded_secret_key


def encrypt_message(encoded_secret_key, file_name):
	# Text to be encrypted is read from file, then deleted for further security
	with open(file_name, "r") as rfile:
            private_msg = rfile.read()
	os.remove(file_name) # File deletion

	# First "translate" variables into the correct format
	decoded_secret_key = base64.b64decode(encoded_secret_key) #Secret key is decoded from its b64 encoded state
	bprivate_msg = str.encode(private_msg) # Private message is translated to bits for it to be encrypted successfully (str can not be encrypted, only bytes can)

	# Generate the cipher for the encryption process
	cipher = AES.new(decoded_secret_key, AES.MODE_CFB)
	encrypted_data = cipher.encrypt(bprivate_msg)

	with open(file_name, "wb") as wfile:
            wfile.write(cipher.iv)
            wfile.write(encrypted_data)
            wfile.close()

def decrypt_message(encoded_secret_key, file_name):
	# Open files and extract ciphered bytes, then delete for further security
	with open(file_name, "rb") as rfile:
		iv = rfile.read(16)
		private_msg = rfile.read()
		rfile.close()

	os.remove(file_name) # File deletion

	# Translate variables into the correcto format
	encoded_secret_key = str.encode(encoded_secret_key)
	decoded_secret_key = base64.b64decode(encoded_secret_key)

	#Find cypher and decrypt data
	cipher = AES.new(decoded_secret_key, AES.MODE_CFB, iv=iv)
	message = cipher.decrypt(private_msg)
	
	with open(file_name, "w") as wfile:
            wfile.write(message.decode())
            wfile.close() 

    

# Create GUI window
import tkinter as tk
from tkinter import filedialog, Text
import os

ventana = tk.Tk() #Crea objeto tk

#Caracterísitcas ventana
ventana.title("dEncrypt") #Título
ventana.geometry("650x400") #Tamaño
ventana.iconphoto(True, tk.PhotoImage(file='dEncrypt_logo.png')) #Icono

files = []

def openApp():
    global filename
    filename = filedialog.askopenfilename(initialdir="\Desktop", title="Select file", 
    filetypes=(("text", "*.txt"), ("allfiles", "*.*")))

    #Display label
    file_label = tk.Label(openFile, text=filename, bg="#808080", fg="white")
    file_label.pack()

def add_to_clipboard():
    text = private_key
    ventana.clipboard_clear()
    ventana.clipboard_append(text)
    
    copy_button = tk.Label(key_canvas, text = "COPIED!", fg = "red").grid(row=0, column=2)


def security_timer():
    times = 10
    while times > -1:
        timer = tk.Label(key_canvas, text = str(times)).grid(row=1, column=1)
        ventana.update()
        time.sleep(1)
        times -= 1
    
    ventana.destroy()

def encrypt_file():
    #Generates PK and encrypts message
    global private_key
    private_key = generate_secret_key_for_AES_cipher()
    encoded_message = encrypt_message(private_key, filename)

    #Returns PK to user for future decryption
    new_key = tk.Label(key_canvas, text = private_key).grid(row=0, column=1)
    copy_button = tk.Button(key_canvas, text = "COPY", command=add_to_clipboard).grid(row=0, column=2)

    security_timer()


def decrypt_file():
    private_key = key.get() 
    if len(private_key) == 0:
        tk.messagebox.showerror(title="PrivateKey Error", message="The Private key must be longer than 0 characters")
    else:
        decoded_message = decrypt_message(private_key, filename)
        security_timer()

#Logo
logo_canvas = tk.Canvas(ventana, width = 300, height = 300)
logo_canvas.place(anchor="center", rely=".45", x="370")
logo = tk.PhotoImage(file="dEncrypt_logo.png")
logo_canvas.create_image(30,30, anchor="nw", image=logo)

#OpenFile button.
#Selects file to be encrypted/decrypted
openFile = tk.Button(ventana, text="Choose file...", padx="10", pady="6", fg="white", bg="#808080", command=openApp)
openFile.place(relx=".55", y=240, anchor="center")


#Keys. User inputs its keys for encryption/decryption
key_canvas = tk.Canvas(ventana, width=70, height = 30)
key_canvas.place(anchor="center", relx =".5", y = 200)

key_label = tk.Label(key_canvas, text="Private Key: ").grid(row=0)
key = tk.Entry(key_canvas)
key.grid(row=0, column=1)


#Encrypt/decrypt. User selects which direction it wants to take.
encrypt_bt = tk.Button(ventana, text="ENCRYPT", padx="50", pady="10", fg="white", bg="#808080", command=encrypt_file)
encrypt_bt.place(relx=".2", y=350, anchor="sw")


decrypt_bt = tk.Button(ventana, text="DECRYPT", padx="50", pady="10", fg="white", bg="#808080", command=decrypt_file)
decrypt_bt.place(relx=".85", y=350, anchor = "se")


#Cerramos bucle GUI
ventana.mainloop()