import tkinter
from tkinter import messagebox
import base64

window= tkinter.Tk()
window.minsize(480,640)

baslik_label=tkinter.Label(text="Lütfen şifre için başlık girin")
baslik_label.pack()

baslik_giris= tkinter.Entry()
baslik_giris.pack()

bilgi_label=tkinter.Label(text="Lütfen saklamak istediğiniz veya kırmak istediğiniz bilgileri girin")
bilgi_label.pack()

bilgi_giris= tkinter.Text()
bilgi_giris.config(width=40)
bilgi_giris.pack()

anahtar_kelime_label= tkinter.Label(text="Lütfen anahtar kelime belirle ve asla unutma")
anahtar_kelime_label.pack()

anahtar_giris=tkinter.Entry()
anahtar_giris.config(width=40)
anahtar_giris.pack()


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def sifrele_kaydet():
    baslik=baslik_giris.get()
    bilgi=bilgi_giris.get("1.0",tkinter.END)
    anahtar=anahtar_giris.get()

    if len(baslik) == 0 or len(bilgi) == 0 or len(anahtar) == 0:
        messagebox.showinfo(title="hata!", message="Lütfen bilgileri doldurun.")
    else:
        message_encrypted = encode(anahtar, bilgi)

        try:
            with open("dosya.txt", "a") as data_file:
                data_file.write(f'\n{baslik}\n{message_encrypted}')
        except FileNotFoundError:
            with open("dosya.txt", "w") as data_file:
                data_file.write(f'\n{baslik}\n{message_encrypted}')
        finally:
            baslik_giris.delete(0,tkinter.END)
            anahtar_giris.delete(0,tkinter.END)
            bilgi_giris.delete("1.0",tkinter.END)
def sifreyi_coz():
    message_encrypted = bilgi_giris.get("1.0",tkinter.END)
    master_secret = anahtar_giris.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="hata!", message="Lütfen bilgileri doldurun.")
    else:
        try:
            decrypted_message = decode(master_secret,message_encrypted)
            bilgi_giris.delete("1.0", tkinter.END)
            bilgi_giris.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="hata!", message="Lütfen bilgileri doldurun. ")



kaydet_ve_sifrele=tkinter.Button(text="Kaydet ve sifrele", command=sifrele_kaydet)
kaydet_ve_sifrele.pack()

sifreyi_kir= tkinter.Button(text="Şifreyi çözümle",command=sifreyi_coz)
sifreyi_kir.pack()
tkinter.mainloop()