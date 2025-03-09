"""Muestra del Módulo Principal de mi Proyecto HORUX ANTIVIRUS, cuya función principal es la detección y eliminación de
Malware por medio del método de comparación de hashes sha256 con registros en bases de datos de empresas como MalwareBazaar mediante API's
y la descarga de BB.DD LOCALES.
"""

if __name__=="__main__":
	from customtkinter import *
	from tkinter import filedialog
	from PIL import Image, ImageTk
	import time, os, pyautogui, datetime
	import tkinter as Tk
	from pathlib import Path
	import hashlib
	import sqlite3
	#import threading
	#import queue
	import json, requests

	class App(CTk):
		def __init__(self):
			super().__init__()
			self.resizable(0,0)
			self.datawin()
			self.geometry("{}".format(self.geometrytxt))
			self.title("Horux Antivirus")
			set_appearance_mode("dark")
			set_default_color_theme("dark-blue")
			self.configure(fg_color="#00000F")
			
			#self.iconphoto(True, ImageTk.PhotoImage(Image.open("../assets/Horux10i.png").resize((100,100), Image.LANCZOS)))
			self.iconbitmap('../assets/Horuxico.ico')
			#self.wm_iconbitmap('../assets/Horuxico.ico')


			self.grid_columnconfigure((0,1,2,3,4,5,6,7,8,9,10,11), weight=0)
			self.grid_rowconfigure((0,1,2,3,4,5,6,7,8,9,10,11), weight=0)

			#self.config(menu=menu_bar)
			self.subwinstts=False
			self.version="v-24.12.18"

			self.level="admin"
			self.actopt=""

			#-------------------------------------CARGA DE IMAGENES-------------------------------------#
			#------------------------------------------Area A-------------------------------------------#

			Cimg1a=Image.open("../assets/optboxnamepro1.png").resize((800,200), Image.LANCZOS)
			img1a=CTkImage(Cimg1a, size=(200,50))
			
			Cimg2a=Image.open("../assets/busc2.png").resize((40,40), Image.LANCZOS)
			img2a=CTkImage(Cimg2a, size=(40,40))
			
			Cimg3a=Image.open("../assets/serclean2.png").resize((40,40), Image.LANCZOS)
			img3a=CTkImage(Cimg3a, size=(40,40))

			Cimg4a=Image.open("../assets/scud2.png").resize((40,40), Image.LANCZOS)
			img4a=CTkImage(Cimg4a, size=(40,40))

			Cimg5a=Image.open("../assets/databaseupload.png").resize((40,40), Image.LANCZOS)
			img5a=CTkImage(Cimg5a, size=(40,40))

			Cimg6a=Image.open("../assets/url3.png").resize((40,40), Image.LANCZOS)
			img6a=CTkImage(Cimg6a, size=(40,40))

			Cimg7a=Image.open("../assets/config2.png").resize((36,36), Image.LANCZOS)
			img7a=CTkImage(Cimg7a, size=(36,36))

			Cimg8a=Image.open("../assets/person2.png").resize((40,40), Image.LANCZOS)
			img8a=CTkImage(Cimg8a, size=(36,36))

			Cimg9a=Image.open("../assets/info2.png").resize((40,40), Image.LANCZOS)
			img9a=CTkImage(Cimg9a, size=(36,36))

			#-------------------------------------CARGA DE IMAGENES-------------------------------------#
			#------------------------------------------Area B-------------------------------------------#
			"""
			Cimg1b=Image.open("../assets/txtavh.png").resize((800,200), Image.LANCZOS)
			img1b=CTkImage(Cimg1b, size=(200+200, 50+50))
			"""

			Cimg1b=Image.open("../assets/txtavh2.png").resize((500,200), Image.LANCZOS)
			img1b=CTkImage(Cimg1b, size=(125+50, 50+20))

			Cimg2b=Image.open("../assets/sa.png").resize((400,200), Image.LANCZOS)
			img2b=CTkImage(Cimg2b, size=(100+50, 50+25))

			Cimg3b=Image.open("../assets/escudo.png").resize((180,200), Image.LANCZOS)
			img3b=CTkImage(Cimg3b, size=(100, 110))

			Cimg4b=Image.open("../assets/statusframe303x140.png").resize((303,140), Image.LANCZOS)
			img4b=CTkImage(Cimg4b, size=(283, 120))


			#-------------------------------------CARGA DE IMAGENES-------------------------------------#
			#-----------------------------------------Area C1-------------------------------------------#
		
			Cimg0c1=Image.open("../assets/btnanalizar.png").resize((400,140), Image.LANCZOS)
			self.img0c1=CTkImage(Cimg0c1, size=(200, 70))

			Cimg1c1=Image.open("../assets/btncancelar.png").resize((400,140), Image.LANCZOS)
			self.img1c1=CTkImage(Cimg1c1, size=(200, 70))

			Cimg2c1=Image.open("../assets/db.png").resize((60,60), Image.LANCZOS)
			self.img2c1=CTkImage(Cimg2c1, size=(60, 60))

			Cimg3c1=Image.open("../assets/dirs.png").resize((70,70), Image.LANCZOS)
			self.img3c1=CTkImage(Cimg3c1, size=(70, 70))

			Cimg4c1=Image.open("../assets/dirset.png").resize((38,38), Image.LANCZOS)
			self.img4c1=CTkImage(Cimg4c1, size=(38, 38))

			Cimg5c1=Image.open("../assets/virus.png").resize((36,36), Image.LANCZOS)
			self.img5c1=CTkImage(Cimg5c1, size=(36, 36))

			"""
			Cimg1c2=Image.open("../assets/statusframeX.png").resize((700,140), Image.LANCZOS)
			img1c2=CTkImage(Cimg1c2, size=(600, 120))

			Cimg3c=Image.open("../assets/escudo.png").resize((180,200), Image.LANCZOS)
			img3c1=CTkImage(Cimg3c3, size=(100, 110))

			Cimg4c=Image.open("../assets/statusframe303x140.png").resize((303,140), Image.LANCZOS)
			img4c1=CTkImage(Cimg1c4, size=(283, 120))
			"""

			#-------------------------------------CARGA DE IMAGENES-------------------------------------#
			#-----------------------------------------Area C2-------------------------------------------#

			Cimg0c2=Image.open("../assets/btnlimpiar.png").resize((400,140), Image.LANCZOS)
			self.img0c2=CTkImage(Cimg0c2, size=(200, 70))

			#-------------------------------------CARGA DE IMAGENES-------------------------------------#
			#-----------------------------------------Area C3-------------------------------------------#

			#-------------------------------------CARGA DE IMAGENES-------------------------------------#
			#-----------------------------------------Area C4-------------------------------------------#

			#-------------------------------------CARGA DE IMAGENES-------------------------------------#
			#-----------------------------------------Area C5-------------------------------------------#

			Cimg0c5=Image.open("../assets/btnconsultar.png").resize((400,140), Image.LANCZOS)
			self.img0c5=CTkImage(Cimg0c5, size=(200-200+133, 70-70+46))

			Cimg1c5=Image.open("../assets/info.png").resize((60,60), Image.LANCZOS)
			self.img1c5=CTkImage(Cimg1c5, size=(60,60))

			Cimg2c5=Image.open("../assets/aten.png").resize((60,60), Image.LANCZOS)
			self.img2c5=CTkImage(Cimg2c5, size=(60,60))

			Cimg3c5=Image.open("../assets/check2.png").resize((60,60), Image.LANCZOS)
			self.img3c5=CTkImage(Cimg3c5, size=(60,60))	

			#-------------------------------------CARGA DE IMAGENES-------------------------------------#
			#-----------------------------------------Area C6-------------------------------------------#

			#-------------------------------------CARGA DE IMAGENES-------------------------------------#
			#-----------------------------------------Area C7-------------------------------------------#

			Cimg1c7=Image.open("../assets/acc.png").resize((100,100), Image.LANCZOS)
			self.img1c7=CTkImage(Cimg1c7, size=(80, 80))



			#-------------------------------------CONTENEDORES-------------------------------------#
			#----------------------------------------Area D----------------------------------------#

			self.menubarframe=CTkFrame(master=self, corner_radius=0, fg_color="#00000f", height=22, width=912)
			self.menubarframe.grid(row=0, column=0, sticky="nsew", columnspan=12, pady=(0,0))
			self.menubarframe.grid_propagate(False)

			"""
			self.menubar=Tk.Menu(self)

			self.menutools=Tk.Menu(self.menubar, tearoff=0)
			self.menutools.add_command(label="Cerrar")
			self.menubar.add_cascade(label="Tools", menu=self.menutools)

			self.menubar.add_cascade(label="Archivo", menu=self.menubar)
			self.menubar.add_command(label="Nuevo")
			self.menubar.add_command(label="Abrir")
			self.configure(menu=self.menubar)
			"""
			#-------------------------------------CONTENEDORES-------------------------------------#
			#----------------------------------------Area A----------------------------------------#
			
			self.optboxframe=CTkFrame(master=self, corner_radius=10,fg_color="#00000f", height=490, width=200)
			self.optboxframe.grid(row=1, column=0, sticky="nsew", rowspan=11, pady=(0,0))
			self.optboxframe.grid_columnconfigure((0,1,2), weight=0)
			self.optboxframe.grid_rowconfigure((0,1,2,3,4,5,6,7), weight=0)
			self.optboxframe.grid_propagate(False)

			#--------------------------------------CONTENEDOR--------------------------------------#
			#--------------------------------------Area B y C--------------------------------------#

			self.priframe=CTkFrame(master=self, corner_radius=10,fg_color="#00cccc", height=490, width=712)
			self.priframe.grid(row=1, column=1, sticky="nsew", rowspan=11, columnspan=11, padx=(0,0), pady=(0,0))
			self.priframe.grid_columnconfigure((0,1,2,3), weight=0)
			self.priframe.grid_rowconfigure((0,1,2,3), weight=0)
			self.priframe.grid_propagate(False)

			#-------------------------------------CONTENEDORES-------------------------------------#
			#----------------------------------------Area B----------------------------------------#

			self.statusframe=CTkFrame(master=self.priframe, corner_radius=10,fg_color="#00000f", height=120, width=706)
			self.statusframe.grid(row=0, column=0, rowspan=1, columnspan=4, padx=(3,0), pady=(3,0))
			self.statusframe.grid_columnconfigure((0,1,2,3), weight=0)
			self.statusframe.grid_propagate(False)


			#-------------------------------------CONTENEDORES-------------------------------------#
			#----------------------------------------Area C----------------------------------------#
			#-------------------------------------- Bienvenida--------------------------------------#
			self.welcframe=CTkFrame(master=self.priframe, corner_radius=10,fg_color="#00000f", height=362, width=706)
			self.welcframe.grid_columnconfigure((0,1,2,3), weight=0)
			self.welcframe.grid_rowconfigure((0,1,2,3), weight=0)
			self.welcframe.grid_propagate(False)


			#----------------------------------------FrameC1---------------------------------------#

			self.opt1frame=CTkFrame(master=self.priframe, corner_radius=10,fg_color="#00000f", height=362, width=706)
			self.opt1frame.grid_columnconfigure((0,1,2,3,4,5), weight=0)
			self.opt1frame.grid_rowconfigure((0,1,2,3,4,5), weight=0)
			self.opt1frame.grid_propagate(False)

			#----------------------------------------FrameC2---------------------------------------#
			self.opt2frame=CTkFrame(master=self.priframe, corner_radius=10,fg_color="#00000f", height=362, width=706)
			self.opt2frame.grid_columnconfigure((0,1,2,3), weight=0)
			self.opt2frame.grid_rowconfigure((0,1,2,3), weight=0)
			self.opt2frame.grid_propagate(False)
			#----------------------------------------FrameC3---------------------------------------#
			self.opt3frame=CTkFrame(master=self.priframe, corner_radius=10,fg_color="#00000f", height=362, width=706)
			self.opt3frame.grid_columnconfigure((0,1,2,3), weight=0)
			self.opt3frame.grid_rowconfigure((0,1,2,3), weight=0)
			self.opt3frame.grid_propagate(False)
			#----------------------------------------FrameC4---------------------------------------#
			self.opt4frame=CTkFrame(master=self.priframe, corner_radius=10,fg_color="#00000f", height=362, width=706)
			self.opt4frame.grid_columnconfigure((0,1,2,3), weight=0)
			self.opt4frame.grid_rowconfigure((0,1,2,3), weight=0)
			self.opt4frame.grid_propagate(False)
			#----------------------------------------FrameC5---------------------------------------#
			self.opt5frame=CTkFrame(master=self.priframe, corner_radius=10,fg_color="#00000f", height=362, width=706)
			self.opt5frame.grid_columnconfigure((0,1,2,3), weight=0)
			self.opt5frame.grid_rowconfigure((0,1,2,3), weight=0)
			self.opt5frame.grid_propagate(False)
			#----------------------------------------FrameC6---------------------------------------#
			self.opt6frame=CTkFrame(master=self.priframe, corner_radius=10,fg_color="#00000f", height=362, width=706)
			self.opt6frame.grid_columnconfigure((0,1,2,3), weight=0)
			self.opt6frame.grid_rowconfigure((0,1,2,3), weight=0)
			self.opt6frame.grid_propagate(False)
			#----------------------------------------FrameC7---------------------------------------#
			self.opt7frame=CTkFrame(master=self.priframe, corner_radius=10,fg_color="#00000f", height=362, width=706)
			self.opt7frame.grid_columnconfigure((0,1,2,3), weight=0)
			self.opt7frame.grid_rowconfigure((0,1,2,3), weight=0)
			self.opt7frame.grid_propagate(False)
			
			self.opt7frame.grid(row=1, column=0, rowspan=3, columnspan=4, padx=(3,0), pady=(2,0))
			#----------------------------------------FrameC8---------------------------------------#
			self.opt8frame=CTkFrame(master=self.priframe, corner_radius=10,fg_color="#00000f", height=362, width=706)
			self.opt8frame.grid_columnconfigure((0,1,2,3), weight=0)
			self.opt8frame.grid_rowconfigure((0,1,2,3), weight=0)
			self.opt8frame.grid_propagate(False)


			#-------------------------------------ELEMENTOS-------------------------------------#
			#--------------------------------------Area D---------------------------------------#

			self.tools=CTkButton(master=self.menubarframe, text="Tools", 
				bg_color="#00000f", fg_color="#131320", width=60, height=10, corner_radius=30, hover_color="#131340", 
				command=lambda:self.buttontoolsbar()).grid(row=0, column=0, padx=(5,1), pady=(1,0))

			self.vista=CTkButton(master=self.menubarframe, text="Vista", 
				bg_color="#00000f", fg_color="#131320", width=60, height=10, corner_radius=30, hover_color="#131340", 
				command=lambda:self.buttonvistabar()).grid(row=0, column=1, padx=(0,1), pady=(1,0))

			self.ayuda=CTkButton(master=self.menubarframe, text="Ayuda", 
				bg_color="#00000f", fg_color="#131320", width=60, height=10, corner_radius=30, hover_color="#131340", 
				command=lambda:self.buttonhelpbar()).grid(row=0, column=2, padx=(0,1), pady=(1,0))

			#-------------------------------------ELEMENTOS-------------------------------------#
			#--------------------------------------Area A---------------------------------------#
			if self.level=="admin":
				self.namelabel=CTkLabel(master=self.optboxframe, text="", image=img1a, 
					fg_color="#00000f", text_color="#898989", font=("Arial", 60))
				self.namelabel.grid(row=0, column=0, columnspan=3, padx=(0,0), pady=(25,5), sticky=("ew"))

				self.botscnnr=CTkButton(master=self.optboxframe, text="     Escanear", image=img2a, anchor="ew", 
					border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=200, height=60, 
					border_width=0 , corner_radius=12, hover_color="#131340", command=self.buttonopt1)
				self.botscnnr.grid(row=1, column=0, columnspan=3, padx=(0,0), pady=(10,5), sticky="")

				self.boturl=CTkButton(master=self.optboxframe, text="     URL Checker", image=img6a, anchor="ew", 
					border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=200, height=60, 
					border_width=0, corner_radius=12, hover_color="#131340", command=self.buttonopt5)
				self.boturl.grid(row=3, column=0, columnspan=3, padx=(0,0), pady=(0,5), sticky="")

				self.botclean=CTkButton(master=self.optboxframe, text="     Limpiador", image=img3a, anchor="ew", 
					border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=200, height=60, 
					border_width=0, corner_radius=12, hover_color="#131340", command=self.buttonopt2)
				self.botclean.grid(row=2, column=0, columnspan=3, padx=(0,0), pady=(0,5), sticky="")

				self.bothistorial=CTkButton(master=self.optboxframe, text="     Historial", image=img4a, anchor="ew", 
					border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=200, height=60, 
					border_width=0, corner_radius=12, hover_color="#131340", command=self.buttonopt3)
				self.bothistorial.grid(row=4, column=0, columnspan=3, padx=(0,0), pady=(0,5), sticky="")

				#"""
				self.botactbd=CTkButton(master=self.optboxframe, text="     Actualizar BBDD", image=img5a, anchor="ew", 
					border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=200, height=60, 
					border_width=0, corner_radius=12, hover_color="#131340", command=self.buttonopt4)
				self.botactbd.grid(row=5, column=0, columnspan=3, padx=(0,0), pady=(0,0), sticky="")
				#"""

				self.versionlabel=CTkLabel(master=self.optboxframe, text=("{}").format(self.version), 
					fg_color="#00000f", text_color="#898989", font=("Arial", 10), height=15)
				self.versionlabel.grid(row=6, column=0, columnspan=3, padx=(0,0), pady=(5+65-60,10), sticky=("ew"))

				self.botconfig=CTkButton(master=self.optboxframe, text="", image=img7a, compound="top", 
					border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=20, height=20, 
					corner_radius=90, hover_color="#131340", command=self.buttonopt6)
				self.botconfig.grid(row=7, column=0, padx=(0,0), pady=(0,0), sticky="e")

				self.botperfil=CTkButton(master=self.optboxframe, text="", image=img8a, compound="top", 
					border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=20, height=20, 
					corner_radius=90, hover_color="#131340", command=self.buttonopt7)
				self.botperfil.grid(row=7, column=1, padx=(1,1), pady=(0,0), sticky="")

				self.botabout=CTkButton(master=self.optboxframe, text="", image=img9a, compound="top", 
					border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=20, height=20, 
					corner_radius=40, hover_color="#131340", command=self.buttonopt8)
				self.botabout.grid(row=7, column=2, padx=(0,0), pady=(0,0), sticky="w")

			elif self.level=="user":
				self.namelabel=CTkLabel(master=self.optboxframe, text="", image=img1a, 
					fg_color="#00000f", text_color="#898989", font=("Arial", 60))
				self.namelabel.grid(row=0, column=0, columnspan=3, padx=(0,0), pady=(25,65-30), sticky=("ew"))

				self.botscnnr=CTkButton(master=self.optboxframe, text="     Escanear", image=img2a, anchor="ew", 
					border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=200, height=60, 
					border_width=0 , corner_radius=12, hover_color="#131340", command=self.buttonopt1)
				self.botscnnr.grid(row=1, column=0, columnspan=3, padx=(0,0), pady=(10,5), sticky="")

				self.boturl=CTkButton(master=self.optboxframe, text="     URL Checker", image=img6a, anchor="ew", 
					border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=200, height=60, 
					border_width=0, corner_radius=12, hover_color="#131340", command=self.buttonopt5)
				self.boturl.grid(row=3, column=0, columnspan=3, padx=(0,0), pady=(0,5), sticky="")

				self.botclean=CTkButton(master=self.optboxframe, text="     Limpiador", image=img3a, anchor="ew", 
					border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=200, height=60, 
					border_width=0, corner_radius=12, hover_color="#131340", command=self.buttonopt2)
				self.botclean.grid(row=2, column=0, columnspan=3, padx=(0,0), pady=(0,5), sticky="")

				self.bothistorial=CTkButton(master=self.optboxframe, text="     Historial", image=img4a, anchor="ew", 
					border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=200, height=60, 
					border_width=0, corner_radius=12, hover_color="#131340", command=self.buttonopt3)
				self.bothistorial.grid(row=4, column=0, columnspan=3, padx=(0,0), pady=(0,5), sticky="")

				"""
				self.botactbd=CTkButton(master=self.optboxframe, text="     Actualizar BBDD", image=img5a, anchor="ew", 
					border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=200, height=60, 
					border_width=0, corner_radius=12, hover_color="#131340", command=self.buttonopt4)
				self.botactbd.grid(row=5, column=0, columnspan=3, padx=(0,0), pady=(0,0), sticky="")
				"""

				self.versionlabel=CTkLabel(master=self.optboxframe, text=("{}").format(self.version), 
					fg_color="#00000f", text_color="#898989", font=("Arial", 10), height=15)
				self.versionlabel.grid(row=6, column=0, columnspan=3, padx=(0,0), pady=(5+65-30,10), sticky=("ew"))

				self.botconfig=CTkButton(master=self.optboxframe, text="", image=img7a, compound="top", 
					border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=20, height=20, 
					corner_radius=90, hover_color="#131340", command=self.buttonopt6)
				self.botconfig.grid(row=7, column=0, padx=(0,0), pady=(0,0), sticky="e")

				self.botperfil=CTkButton(master=self.optboxframe, text="", image=img8a, compound="top", 
					border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=20, height=20, 
					corner_radius=90, hover_color="#131340", command=self.buttonopt7)
				self.botperfil.grid(row=7, column=1, padx=(1,1), pady=(0,0), sticky="")

				self.botabout=CTkButton(master=self.optboxframe, text="", image=img9a, compound="top", 
					border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=20, height=20, 
					corner_radius=40, hover_color="#131340", command=self.buttonopt8)
				self.botabout.grid(row=7, column=2, padx=(0,0), pady=(0,0), sticky="w")

			#-------------------------------------ELEMENTOS-------------------------------------#
			#--------------------------------------Area B---------------------------------------#
			
			self.icostatus=CTkLabel(master=self.statusframe, image=img3b, text="")
			self.icostatus.grid(row=0, column=0, columnspan=1, padx=(10,0), pady=(3,3), sticky="w")
			
			self.txtstatus=CTkLabel(master=self.statusframe, image=img2b, text="")
			self.txtstatus.grid(row=0, column=1, columnspan=1, padx=(10,0), pady=(3,3), sticky="w")
			
			self.logostatus=CTkLabel(master=self.statusframe, image=img4b, text="")
			self.logostatus.grid(row=0, column=2, columnspan=1, padx=(145,10), pady=(0,0), sticky="")
			#703-600-10,10
			"""
			self.actstatus=CTkLabel(master=self.statusframe, image=img2b, text="")
			self.actstatus.grid(row=0, column=1, columnspan=1, padx=(703-600-10,10), pady=(0,0), sticky="e")

			
			self.icostatus=CTkLabel(master=self.statusframe, image=img1b, text="")
			self.icostatus.grid(row=0, column=0, columnspan=1, padx=(8,0), pady=(0,0))
			
			#Canvas Object
			self.statuscanvas=Tk.Canvas(self.statusframe, width=120, height=118)
			self.statuscanvas.grid(row=0, column=0, columnspan=1, padx=(0,0), pady=(0,0))

			self.canvasimg1b=ImageTk.PhotoImage(Cimg1b)

			self.statuscanvas.create_image(120, 120, image=self.canvasimg1b)
			self.statusframe.wm_attributes('-transparentcolor', 'white')
			
			self.hour=CTkLabel(master=self.statusframe, text=(""), 
				fg_color="#00000f", text_color="#898989", font=("Arial", 10), height=15)
			self.hour.grid(row=0, column=1, columnspan=1, padx=(563-63,0), pady=(0,0), sticky=("ne"))
			"""

			#--------------------------------------------------------------------------FUNCIONES--------------------------------------------------------------------------#
			"""Aprendizaje, si genero desde la función, un label, se colocará, y siempre se colocará, uno encima de otro, hay que asegurarse de
			eliminar el elemento que quede por debajo si es requerido para ahorrar recursos"""
			




		def quitframes(self,nf):
			self.listframes=self.opt1frame, self.opt2frame, self.opt3frame, self.opt4frame, self.opt5frame, self.opt6frame, self.opt7frame, self.opt8frame
			#Al empezar el analisis. Congelar la ventana!. Para que no se pueda interaccionar y evitar problemas
			for frame in self.listframes:
				if self.listframes[nf]==frame:
					continue
				frame.grid_forget()
				for widget in frame.winfo_children():
					widget.destroy()
			del self.listframes

		def inhabilitador(self):
			self.listbuttons=(self.botscnnr, self.botclean, self.bothistorial, self.boturl, self.botconfig, self.botperfil, self.botabout)
			for bot in self.listbuttons:
				bot.configure(state=DISABLED)
			del self.listbuttons
		
		def habilitador(self):
			self.listbuttons=(self.botscnnr, self.botclean, self.bothistorial, self.boturl, self.botconfig, self.botperfil, self.botabout)
			for bot in self.listbuttons:
				bot.configure(state=NORMAL)
			del self.listbuttons

		def servicioenejecucion(self,fxn):
			self.topse=CTkToplevel(self, fg_color="#00000f")
			self.topse.title("Servicio en Ejecución")

			self.pregunta=CTkLabel(master=self.topse, text=("¿Seguro que desea cerrar Horux?"), 
				fg_color="#00000f", text_color="#898989", font=("Calibri", 14), height=15)
			self.pregunta.grid(row=0, column=0, columnspan=3, padx=(0,0), pady=(0+65-30,10), sticky=("ew"))

			"""
			self.sitopse=CTkButton(master=self.topse, text="Sí", 
				border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=20, height=20, 
				corner_radius=40, hover_color="#131340", command=self.destroy())
			self.sitopse.grid(row=1, column=0, padx=(0,0), pady=(0,0), sticky="w")
			"""

			self.topse.overrideredirect(0)
			self.topse.grid_propagate(False)
			self.topse.geometry("400x200+{}+{}".format(self.ubix+456-200,self.ubiy+100))
			#self.topse.transient(self)
			#¿Seguro de que desea cerrar? Análisis en proseso

		
		#--------------------------------------------------------------------------OPT1---------------------------------------------------------------------------#
		def buttonopt1(self):
			self.quitframes(0)
			#Comprobar si el boton ya esta ejecutado
			
			self.opt1frame.grid_propagate(False)
			
			if os.name=="nt":
				self.dirscan=os.environ.get('USERPROFILE')
			elif os.name=="posix":
				self.dirscan=os.environ.get('HOME')
			self.dbselected="Local"

			def eliminarvirus():
				print("Operación para eliminar iniciada")
				self.txtcountvirus.configure(text_color="#ffffff")
				self.txtcountvirus.configure(text="0")

				for valor in self.malwareinfo.values():
					try:
						os.remove(valor)
						print(f"Archivo '{valor}' eliminado correctamente.")
						
					except FileNotFoundError:
						print(f"Error: El archivo '{valor}' no existe.")
					except OSError as e:  # Captura otros errores del sistema operativo
						print(f"Error al eliminar el archivo: {e}")
				
				"""
				try:
					print(self.malwareinfo)
				except:
					print("No hay virus identificados para eliminar")
				"""

				def registrador(directorio):
				    try:
				        #Obtener la fecha y hora actual
				        ahora=datetime.datetime.now()

				        # Formatear la fecha y hora para el nombre del archivo
				        regname=f"Operacion {ahora.strftime('%d-%m-%Y %H%M')}.txt"

				        # Unir el directorio y el nombre del archivo para obtener la ruta completa
				        self.ruta_completa=os.path.join(directorio, regname)

				        print(self.ruta_completa)
				        # Verificar si el directorio existe. Si no, se crea.
				        os.makedirs(directorio, exist_ok=True) #exist_ok evita un error si ya existe

				        # Abrir el archivo en modo escritura ("w"). Si el archivo no existe, se crea.
				        with open(self.ruta_completa, "w") as archivo:
				            # Escribir contenido en el archivo
				            archivo.write("Operación realizada el: " + ahora.strftime('%d/%m/%Y %H:%M:%S\nInformación sobre Virus Eliminados:\n\n'))
				        print(f"Archivo creado exitosamente en: {self.ruta_completa}")
				  
				    except OSError as e: #Manejo de errores de sistema de archivos
				        print(f"Error al crear el archivo: {e}")
				  
				    except Exception as e:
				        print(f"Ocurrió un error inesperado: {e}")

				#AGREGAR INFORMACION AL ARCHIVO CREADO
				def save_data(diccionario, nombre_archivo):
					print("save_data")					
					try:
						with open(nombre_archivo, 'a', encoding='utf-8') as archivo:
							for clave, valor in diccionario.items():
								linea=f"{clave},{valor}\n"
								archivo.write(linea)

						print(f"Diccionario guardado en {nombre_archivo}")

					except Exception as e:
						print(f"Ocurrió un error al guardar el archivo: {e}")			
				try:
					if not bool(self.malwareinfo):
						print("El diccionario está vacío")
					
					else:
						registrador("../userdata/history/")
						save_data(self.malwareinfo, self.ruta_completa)
				except:
					pass
				self.malwareinfo={}

			def visualizar():
				print("Visualizando lista de virus encontrados actuales")
				self.malwarelist=CTkToplevel(self, fg_color="#00000f")
				self.malwarelist.title("Malware Detectado")
				self.malwarelist.overrideredirect(0)
				self.malwarelist.grid_propagate(False)
				self.malwarelist.geometry("400x400+{}+{}".format(self.ubix+456-200,self.ubiy+60))
				#toplabel donde se muestre lineas de info

			def especificdb(eleccionopt1):
				if eleccionopt1=="Predeterminado":
					self.dbselected="Local"
				elif eleccionopt1=="BB.DD. Local":
					self.dbselected="Local"
				elif eleccionopt1=="BB.DD. Online":
					self.dbselected="Online"

				print(self.dbselected)
			def especificdir(eleccionopt1):
				if os.name=="nt":
					if eleccionopt1=="Predeterminado":
						self.dirscan=os.environ.get('USERPROFILE')
						#Colocar en label la dir
					elif eleccionopt1=="Carpetas Personales":
						self.dirscan=os.environ.get('USERPROFILE')
					elif eleccionopt1=="Archivos del Sistema":
						self.dirscan=os.environ.get('USERPROFILE')#RUTA PENDIENTE, EXCLUIR LA CARPETA PERSONAL
					elif eleccionopt1=="Escaneo Completo":
						self.dirscan=os.environ.get('USERPROFILE')#RUTA PENDIENTE, COLOCAR LA RAIZ
					elif eleccionopt1=="Directorio Específico":
						self.dirscan=filedialog.askdirectory()
					elif eleccionopt1=="Archivo Específico":
						self.dirscan=filedialog.askopenfilename()
					else:
						self.dirscan=filedialog.askdirectory()
				elif os.name=="posix":
					if eleccionopt1=="Predeterminado":
						self.dirscan=os.environ.get('HOME')
						#Colocar en label la dir
					elif eleccionopt1=="Carpetas Personales":
						self.dirscan=os.environ.get('HOME')
					elif eleccionopt1=="Archivos del Sistema":
						self.dirscan=os.environ.get('HOME')#RUTA PENDIENTE
					elif eleccionopt1=="Escaneo Completo":
						self.dirscan=os.environ.get('HOME')#RUTA PENDIENTE
					elif eleccionopt1=="Directorio Específico":
						self.dirscan=filedialog.askdirectory()
					elif eleccionopt1=="Archivo Específico":
						self.dirscan=filedialog.askopenfilename()	
					else:
						self.dirscan=filedialog.askdirectory()

				self.labeldiropt1.configure(text="Ruta: {}".format(self.dirscan))
				
			def cancelaropt1():
				self.varcancel=True
			
			def analizaropt1():
				self.inhabilitador()
				self.protocol("WM_DELETE_WINDOW", lambda:self.servicioenejecucion(0))
				self.progreso1.configure(progress_color="#00cccc")
				print("Directorio escogido",self.dirscan)
				#self.analizaropt1.configure(state=DISABLED)
				
				self.cancelaropt1.grid(row=0, column=0, columnspan=1, rowspan=1, padx=(0,0), pady=(5,0), sticky="new")
				self.analizaropt1.grid_forget()

				self.textboxopt1.configure(state="normal")

				self.malwareinfo={}

				self.countmalware=0
				self.txtcountvirus.configure(text_color="#000000")
				self.txtcountvirus.configure(text="0")

				self.varcancel=False

				def b_dconsult1(hash1,ruta):
			
					def comprobar_texto(texto, base_datos):
					    conn=sqlite3.connect(base_datos)
					    cursor = conn.cursor()
					    #Consulta para verificar si el texto existe
					    cursor.execute("SELECT * FROM fullhash WHERE sha256=?", (hash1,))
					    resultado = cursor.fetchone()
					    conn.close()
					    return resultado is not None
					
					if comprobar_texto(hash1, "../db/fullhashdemo.db"):
						print("Virus Detectado!")
						self.countmalware+=1
						self.txtcountvirus.configure(text_color="#eb4034")
						self.txtcountvirus.configure(text=self.countmalware)
						self.txtcountvirus.update()

						self.malwareinfo[hash1]=ruta

						
					else:
						#print("Archivo no existe en la base de datos")#print(hash1)
						pass

				def apiconsult1(hash1, ruta):
							data={'query': 'get_info', 'hash': '{}'.format(hash1)}
							response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data)
							if response.status_code==200:
								print('Solicitud exitosa')
								try:
									print(response.status_code)
									print(type(response.status_code))
									json1=json.loads(response.text)
								except:
									print("JSON de la API no válido")
								else:
									query_status=json1["query_status"]
									if query_status=="hash_not_found":
										print("Archivo No Malicioso")
										#Practica malicioso
										print("Archivo Malicioso, hash: ", hash1, " Ubicacion: ", Path(ruta))
										self.textboxopt1.insert("0.0", "{}\n".format(hashtmp))
									
									elif query_status=="ok":
										data=json1["data"][0]
										print("Archivo Malicioso, hash: ", hash1, " Ubicacion: ", Path(ruta))
										print(data["sha256_hash"])
										print(data["file_name"])

										self.textboxopt1.insert("0.0", "{}\n".format(hashtmp))
										#guardar dir de Amenaza
										self.countmalware+=1
										self.dirsmalware.append(ruta)

									elif query_status=="illegal_hash":
										print("Hash emitido no válido")
									else:
										print("Error desconocido")
							else:
								print('Error en la solicitud:', response.status_code)
							#SHOW()

				def peso_total_get(ruta):
					peso_total=0
					countar=0
					for p in Path(ruta).rglob('*'):
						if p.is_file():
							peso_total+=p.stat().st_size
							countar+=1
					return f"{peso_total/1024**3:.3f} GB", countar

				peso_dir_ar, canfiles=peso_total_get(self.dirscan)
				print("Peso Total: ", peso_dir_ar, "Cantidad de archivos: ",canfiles)

				def FdX(ruta, canfiles):
					#colaFdX1=queue.Queue()
					#peso_relativo=0
					self.txtcountvirus.configure(text_color="#eb4034")
					count=0
					if Path(ruta).is_dir():

						for path in Path(ruta).rglob('*'):
							if self.varcancel==False:
								if path.is_dir():
									pass
								if path.is_file():
									#cporcentual+=+1/(canfiles)*100
									count=count+1
									cporcentual=(count)/(canfiles)*100
									self.progreso1.set(cporcentual/100)
									self.progreso1.update()

									self.txtcountfiles.configure(text=count)
									self.txtcountfiles.update()

									self.textboxopt1.insert("0.0", "{}\n".format(path))

									#Incrementar el count en el frame derecho
									
									#colaFdX1.put(path)
									#return colaFdX1
									#peso_relativo+=path.stat().st_size

									with open(path, 'rb') as f:
										sha256_hash = hashlib.sha256()
										for byte_block in iter(lambda: f.read(4096), b''):
											sha256_hash.update(byte_block)
									hashtmp=str(sha256_hash.hexdigest())

									#print(path, hashtmp)
									
									if self.dbselected=="Online":
										apiconsult1(hashtmp, path)
										pass
									elif self.dbselected=="Local":
										b_dconsult1(hashtmp, path)
										#show()
										pass
							elif self.varcancel==True:
								break


					elif Path(ruta).is_file():

						with open(Path(ruta), "rb") as f:
							sha256_hash = hashlib.sha256()
							for byte_block in iter(lambda: f.read(4096),b""):
								sha256_hash.update(byte_block)
						#print(sha256_hash.hexdigest())
						hashtmp=str(sha256_hash.hexdigest())
						self.textboxopt1.insert("0.0", "{}\n".format(hashtmp))

						if self.dbselected=="Online":
							apiconsult1(hashtmp, ruta)
						elif self.dbselected=="Local":
							b_dconsult1(hashtmp, ruta)

					#colaFdX1.put(None)
					#return colaFdX1

				FdX(self.dirscan, canfiles)

				#hiloFdX1=threading.Thread(target=lambda:HScan.FdX(self.dirscan))
				#hiloFdX1.start()

				"""
				def updateinfo():
					while True:
						result=colaFdX1.get()
						if result is None:
							break
						self.textboxopt1.insert("0.0","{}\n".format(result))
						self.textboxopt1.update()
				"""
				#hiloGUI1=threading.Thread(target=act)
				#hiloGUI1.start()

				self.textboxopt1.insert("0.0", "Escaneo Finalizado, revise el Estado\n\n\n\n".format(0,0))
				self.protocol("WM_DELETE_WINDOW", lambda:self.destroy())
				#self.analizaropt1.configure(state=NORMAL) esto fue antes del btncancel
				self.habilitador()
				self.textboxopt1.configure(state="disabled")
				
				self.analizaropt1.grid(row=0, column=0, columnspan=1, rowspan=1, padx=(0,0), pady=(5,0), sticky="new")
				self.cancelaropt1.grid_forget()

				try:
					self.topse.destroy()
				except:
					pass

			##########################################^FUNCIONES^##########################################
			###############################################################################################

			###############################################################################################
			##########################################-ELEMENTOS-##########################################


			self.areadebotones=CTkFrame(master=self.opt1frame, fg_color="#00000f",
				height=120, border_width=0, border_color="#004d4d", corner_radius=0)
			self.areadebotones.grid(row=0, column=0, rowspan=3, columnspan=4, padx=(10,0), pady=(5,0), sticky=("nsew"))
			self.areadebotones.grid_propagate(False)

			self.analizaropt1=CTkButton(master=self.areadebotones, image=self.img0c1, text="", anchor="", text_color="#00000f", 
				border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=0, height=0, border_width=0, 
				corner_radius=12, hover_color="#00000f", command=analizaropt1)
			self.analizaropt1.grid(row=0, column=0, columnspan=1, rowspan=1, padx=(0,0), pady=(5,0), sticky="")

			self.cancelaropt1=CTkButton(master=self.areadebotones, image=self.img1c1, text="", anchor="", text_color="#00000f", 
				border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=0, height=0, border_width=0, 
				corner_radius=12, hover_color="#00000f", command=cancelaropt1)


			self.optsetopt1=CTkFrame(master=self.areadebotones, fg_color="#00000f",
				height=122, width=446, border_width=0, border_color="#004d4d")
			self.optsetopt1.grid(row=1, column=0, rowspan=1, columnspan=1, padx=(0,0), pady=(10,0), sticky=(""))

			self.optsetopt1.grid_columnconfigure((0,1,2,3), weight=0)
			self.optsetopt1.grid_rowconfigure((0,1,2), weight=0)
			self.optsetopt1.grid_propagate(True)


			#ofrecer en este frame información: contador de amenazas y enlistar sus direcciones. y además...
			#botón rojo para eliminar y registrarlos en un fichero externo
			self.estadoop1=CTkFrame(master=self.opt1frame, fg_color="#00000f",
				height=180, width=240, border_width=1, border_color="#004d4d", corner_radius=10)
			self.estadoop1.grid(row=0, column=4, rowspan=3, columnspan=2, padx=(0,0), pady=(10,0), sticky=("e"))
			self.estadoop1.grid_columnconfigure((0,1), weight=0)
			self.estadoop1.grid_rowconfigure((0,1,2,4), weight=0)
			self.estadoop1.grid_propagate(False)

			self.topstatus=CTkLabel(master=self.estadoop1, fg_color="#00000f", text="Estado", text_color="#004d4d", height=20, width=240-4, font=("Calibri", 28, "bold"))
			self.topstatus.grid(row=0, column=0, columnspan=2, rowspan=1, padx=(2), pady=(5,0))

			self.imgcountfiles=CTkLabel(master=self.estadoop1, fg_color="#00000f", compound="left", anchor="w", image=self.img4c1, text="  Archivos escaneados:  ",
				text_color="#004d4d", height=20, width=100, font=("Arial", 12, "bold"))
			self.imgcountfiles.grid(row=1, column=0, columnspan=1, rowspan=1, pady=(10,0), padx=(5,0))

			self.txtcountfiles=CTkLabel(master=self.estadoop1, fg_color="#00000f", text="0",
				text_color="#ffffff", height=20, width=36, font=("Arial", 18, "bold"))
			self.txtcountfiles.grid(row=1, column=1, columnspan=1, rowspan=1, pady=(10,0), sticky="w")

			self.imgcountvirus=CTkLabel(master=self.estadoop1, fg_color="#00000f", compound="left", anchor="w", image=self.img5c1, text="   Malwares encontrados:",
				text_color="#004d4d", height=20, width=100, font=("Arial", 12, "bold"))
			self.imgcountvirus.grid(row=2, column=0, columnspan=1, rowspan=1, pady=(10,0), padx=(5,0))

			self.txtcountvirus=CTkLabel(master=self.estadoop1, fg_color="#00000f", text="0",
				text_color="#ffffff", height=20, width=36, font=("Arial", 18, "bold"))
			self.txtcountvirus.grid(row=2, column=1, columnspan=1, rowspan=1, pady=(10,0), sticky="w")

			self.eliminarbtn=CTkButton(master=self.estadoop1, text="Eliminar", text_color="#ffffff", border_width=0, border_color="#eb4034",
				bg_color="#00000f", fg_color="#004d4d", width=100, height=30, corner_radius=40, hover_color="#eb4034", command=eliminarvirus)
			self.eliminarbtn.grid(row=3, column=0, columnspan=2, padx=(70,0), pady=(10,0), sticky="w")

			"""
			self.visualizarbtn=CTkButton(master=self.estadoop1, text="Detalles", text_color="#ffffff", border_width=0, border_color="#eb4034",
				bg_color="#00000f", fg_color="#004d4d", width=100, height=30, corner_radius=40, hover_color="#00cccc", command=visualizar)
			self.visualizarbtn.grid(row=3, column=0, columnspan=2, padx=(125,0), pady=(10,0), sticky="w")
			"""

			###############################################################################################

			self.imgdbopt1=CTkLabel(master=self.optsetopt1, fg_color="#00000f", text="", image=self.img2c1)
			self.imgdbopt1.grid(row=0, column=0, rowspan=3)


			self.textdbopt1=CTkLabel(master=self.optsetopt1, fg_color="#00000f", text="Base de Datos", text_color="#00cccc", height=20, width=100, font=("Arial", 14, "bold"))
			self.textdbopt1.grid(row=0, column=1, columnspan=1, rowspan=1, pady=(0,0))

			self.setdb=CTkOptionMenu(master=self.optsetopt1, width=150, height=20, fg_color="#00cccc", button_color="#00cccc", button_hover_color="#004d4d", 
				text_color="#03033e", anchor="center", dropdown_fg_color="#00000f", dropdown_hover_color="#004d4d", dropdown_text_color="#00cccc", 
				dynamic_resizing=True, command=especificdb)
			self.setdb.configure(values=["{}".format("Predeterminado"), "BB.DD. Local", "BB.DD. Online"])
			self.setdb.set("BB.DD. Local")
			#self.setdb.grid_propagate(False)
			self.setdb.grid(row=1, column=1, columnspan=1, rowspan=1, padx=(0,0), pady=(0,0), sticky=(""))
			#si hay problemas de conexion, mostrar al usuario que configure la base de datos en local

			
			self.imgdiropt1=CTkLabel(master=self.optsetopt1, fg_color="#00000f", text="", image=self.img3c1)
			self.imgdiropt1.grid(row=0, column=2, rowspan=3, padx=(0,0))

			self.textdiropt1=CTkLabel(master=self.optsetopt1, fg_color="#00000f", text="Directorio", text_color="#00cccc", height=20, width=100, font=("Arial", 14, "bold"))
			self.textdiropt1.grid(row=0, column=3, columnspan=1)

			self.setdirs=CTkOptionMenu(master=self.optsetopt1, width=150, height=20, fg_color="#00cccc", button_color="#00cccc", button_hover_color="#004d4d", 
				text_color="#03033e", anchor="center", dropdown_fg_color="#00000f", dropdown_hover_color="#004d4d", dropdown_text_color="#00cccc", 
				dynamic_resizing=False, command=especificdir)
			#Colocar en la personalizada, el nombre del archivo O del directorio sin supradirectorios
			self.setdirs.configure(values=["Predeterminado","Directorio Específico", "Archivo Específico", "Archivos del Sistema", "Escaneo Completo"])
			self.setdirs.set("Predeterminado")
			#self.setdirs.grid_propagate(False)
			self.setdirs.grid(row=1, column=3, columnspan=1, rowspan=1, padx=(0,0), pady=(0,0), sticky=(""))


			self.labeldiropt1=CTkLabel(master=self.areadebotones, fg_color="#00000f", text="{}".format(self.dirscan), text_color="#00cccc", width=100, font=("Arial", 10))
			self.labeldiropt1.grid(row=2, column=0, columnspan=4)

			###############################################################################################


			self.areatextyprogressop1=CTkFrame(master=self.opt1frame, fg_color="#00000f",
				height=180, width=240, border_width=0, border_color="#004d4d", corner_radius=0)
			self.areatextyprogressop1.grid(row=3, column=0, rowspan=3, columnspan=6, padx=(10,0), pady=(10,0), sticky=("s"))

			self.textboxopt1=CTkTextbox(master=self.areatextyprogressop1, width=686, height=150, corner_radius=10, text_color="#004d4d", font=("Calibri", 14),
				border_width=1, border_color="#004d4d", bg_color="#00000f", fg_color="#00000f", scrollbar_button_color="#00cccc", scrollbar_button_hover_color="#00fff6")
			self.textboxopt1.insert("0.0", "Seleccione una ruta o archivo específico. Para comenzar, pulse el botón Analizar\n\n\n\n".format(0,0))
			self.textboxopt1.grid(row=3, column=0, rowspan=2, columnspan=6, sticky="", padx=(0,0), pady=(0,0))
			self.textboxopt1.configure(state="disabled")

			self.progreso1=CTkProgressBar(master=self.areatextyprogressop1, orientation="horizontal", fg_color="#004d4d",
			 progress_color="#004d4d", bg_color="#00000f", height=6, width=686)
			
			self.progreso1.set(0)
			self.progreso1.grid(row=5, column=0, rowspan=1, columnspan=6, sticky="", padx=(0,0), pady=(3,0))

			##########################################-ELEMENTOS-##########################################
			###############################################################################################

			self.opt1frame.grid(row=1, column=0, rowspan=3, columnspan=4, padx=(3,0), pady=(2,0))

		#--------------------------------------------------------------------------OPT2---------------------------------------------------------------------------#
		def buttonopt2(self):
			self.opt2frame.grid_propagate(False)
			
			"""
			self.tabview=CTkTabview(master=self.opt2frame)
			self.tabview.grid(row=3, column=0, columnspan=4, sticky="ew", padx=(20,20), pady=(90,0))

			self.tabview.add("Archivos")  # add tab at the end
			self.tabview.add("Registro")  # add tab at the end
			self.tabview.set("3...")  # set currently visible tab

			self.frameredondoprueba=CTkFrame(master=self.opt1frame, corner_radius=100, width=200, height=200)
			self.frameredondoprueba.grid(row=1, column=1, rowspan=2, columnspan=2, padx=(240,0), pady=(60,0))
			self.frameredondoprueba.grid_propagate(False)
	
			self.numerosvariantes=CTkLabel(master=self.frameredondoprueba, image=self.img2a)
			self.numerosvariantes.grid(row=0, column=0, padx=100, pady=100)

			"""
			
			self.opt2frame.grid(row=1, column=0, rowspan=3, columnspan=4, padx=(3,0), pady=(2,0))
			self.quitframes(1)
			print("Limpiando...")


		#--------------------------------------------------------------------------OPT---------------------------------------------------------------------------#
		def buttonopt3(self):
			self.opt3frame.grid_propagate(False)

			self.tituloopt3=CTkLabel(master=self.opt3frame, text="Historial", width=686, height=40,
				fg_color="#00000f", text_color="#00cccc", font=("Calibri", 32, "bold"))
			self.tituloopt3.grid(row=0, column=0, columnspan=6, padx=(10,0), pady=(3,0), sticky=(""))
			self.positionyinc=-1

			self.subframescr=CTkScrollableFrame(master=self.opt3frame, corner_radius=10,fg_color="#00000f", height=362-85, width=706-45,
				border_width=0, border_color="#00cccc")
			self.subframescr.grid_columnconfigure((0,40), weight=0)
			self.subframescr.grid_rowconfigure((0,40), weight=0)
			
			def crear_widgets_por_archivos(historydir, contenedor):
				try:
					archivos = os.listdir(historydir)
					for archivo in archivos:
						ruta_completa = os.path.join(historydir, archivo)
						if os.path.isfile(ruta_completa):
							self.positionyinc+=1
							# Crea una etiqueta con el nombre del archivo
							etiqueta=CTkLabel(contenedor, text=archivo, anchor="w",justify="left", fg_color="#00000f", text_color="#00cccc", font=("Calibri", 16, "bold"),
								height=20, width=362-85-20)
							etiqueta.grid(row=self.positionyinc, column=1, padx=(40,0),pady=(0,8)) #Separación vertical entre widgets.
							#Crea un botón para cada archivo
							self.ruta_absoluta=os.path.abspath(ruta_completa)
							def comando_boton(ruta_completa=ruta_completa): #Función anidada para pasar el parámetro correcto
								def abrir_archivo():
									try:
										os.startfile(self.ruta_absoluta) #Abre el archivo con la aplicación predeterminada
									except FileNotFoundError:
										print(f"Archivo no encontrado: {self.ruta_absoluta}")
									except Exception as e:
										print(f"Error al abrir el archivo: {e}")

								return abrir_archivo
							boton_abrir=CTkButton(contenedor, text="Abrir", border_width=0, border_color="#00cccc",
								bg_color="#00000f", fg_color="#004d4d", width=60, height=30, corner_radius=40, hover_color="#00cccc", command=comando_boton())
							boton_abrir.grid(row=self.positionyinc, column=0, pady=(0,10))

				except FileNotFoundError:
					print(f"Error: El directorio '{historydir}' no existe.")
				except OSError as e:
					print(f"Error al acceder al directorio: {e}")


				"""
				# Limpia los widgets anteriores si hay una nueva selección
				for widget in frame_archivos.winfo_children():
					widget.destroy()
				"""

			crear_widgets_por_archivos("../userdata/history/", self.subframescr)


			

			print("Historial...")
			self.quitframes(2)
			self.opt3frame.grid(row=1, column=0, rowspan=3, columnspan=4, padx=(3,0), pady=(2,0))
			self.subframescr.grid(row=1, column=0, rowspan=3, columnspan=4, padx=(10,0), pady=(10,0))

		#--------------------------------------------------------------------------OPT---------------------------------------------------------------------------#
		def buttonopt4(self):
			self.quitframes(3)
			self.opt4frame.grid_propagate(False)
			
			"""
			#self.opt3frame=CTkScrollableFrame(master=self.priframe, corner_radius=10,fg_color="#00000f", height=360, width=703)
			self.opt3frame=CTkScrollableFrame(master=self.priframe, corner_radius=10,fg_color="#00000f", height=340, width=670)
			self.opt3frame.grid_columnconfigure((0,1,2,3), weight=0)
			self.opt3frame.grid_rowconfigure((0,1,2,3), weight=0)
			#self.opt3frame.grid_propagate(False)
			"""



			print("Actualizar BBDD...")
			self.opt4frame.grid(row=1, column=0, rowspan=3, columnspan=4, padx=(3,0), pady=(2,0))

		#--------------------------------------------------------------------------OPT---------------------------------------------------------------------------#
		def buttonopt5(self):
			self.quitframes(4)
			self.opt5frame.grid_propagate(False)

			def analizaropt5(url):
				ur=url
				print("Analizando URL", ur)
			
				def comprobar_texto(texto, base_datos):
					conn=sqlite3.connect(base_datos)
					cursor=conn.cursor()

					cursor.execute("SELECT * FROM fullurl WHERE url=?", (url,))
					resultado = cursor.fetchone()
					conn.close()
					return resultado is not None

				if comprobar_texto(url, "../db/fullurl.db"):
					self.resultopt5.configure(image=self.img2c5, text="  La dirección URL consultada representa un potencial Riesgo", text_color="#eb4034")
				else:
					self.resultopt5.configure(image=self.img3c5, text="  La dirección URL consultada es Potencialmente Segura", text_color="#2cfdb7")

			#Escribir URL Checker
			self.tituloopt5=CTkLabel(master=self.opt5frame, text="URL Checker", width=686, height=40,
				fg_color="#00000f", text_color="#00cccc", font=("Calibri", 32, "bold"))
			self.tituloopt5.grid(row=0, column=0, columnspan=6, padx=(10,0), pady=(10,0), sticky=(""))

			self.info1opt5=CTkLabel(master=self.opt5frame, text="Introduce la URL sospechosa", width=686, height=40,
				fg_color="#00000f", text_color="#ffffff", font=("Calibri", 20, "bold"))
			self.info1opt5.grid(row=1, column=0, columnspan=6, padx=(10,0), pady=(20,10), sticky=(""))

			self.inputurl=CTkEntry(master=self.opt5frame, corner_radius=30, border_color="#00cccc", border_width=2, font=("Arial", 18), 
				fg_color="#00000f", text_color="#898989", height=40, width=683-260-3)
			self.inputurl.grid(row=2, column=0, columnspan=6, padx=(10,0), pady=(0,0), sticky=(""))

			self.info2opt5=CTkLabel(master=self.opt5frame, text="Copia o Pega URLs usando 'Ctrl+C' y 'Ctrl+V'", width=686, height=20,
				fg_color="#00000f", text_color="#004d4d", font=("Calibri", 12, "bold"))
			self.info2opt5.grid(row=3, column=0, columnspan=6, padx=(10,0), pady=(0,0), sticky=(""))

			self.btnurlopt5=CTkButton(master=self.opt5frame, image=self.img0c5, text="", anchor="", text_color="#00000f", 
				border_color="#00000f", bg_color="#00000f", fg_color="#00000f", width=0, height=0, border_width=0, 
				corner_radius=12, hover_color="#00000f", command=lambda:analizaropt5(self.inputurl.get()))
			self.btnurlopt5.grid(row=5, column=0, columnspan=6, rowspan=1, padx=(0,0), pady=(5,0), sticky="")

			self.resultopt5=CTkLabel(master=self.opt5frame, image=self.img1c5, text="  Consulta una dirección URL...", width=260, height=20,
				fg_color="#00000f", text_color="#00cccc", font=("Calibri", 22, "bold"), compound="left")
			self.resultopt5.grid(row=6, column=0, columnspan=6, padx=(0,0), pady=(30,0), sticky=(""))

			self.resultopt5.configure(image=self.img1c5, text="  Consulta una dirección URL...", text_color="#00cccc")

			"""
			self.img1c5 info
			self.img2c5 aler
			self.img3c5 check
			"""

			#Boton Enviar
			#Resultados
			#Añadir al firewall

			print("Analizando URL...")
			self.opt5frame.grid(row=1, column=0, rowspan=3, columnspan=4, padx=(3,0), pady=(2,0))

		#--------------------------------------------------------------------------OPT---------------------------------------------------------------------------#
		def buttonopt6(self):
			self.quitframes(5)
			self.opt6frame.grid_propagate(False)
			"""
			self.tituloopt6=CTkLabel(master=self.opt6frame, text="Configuración", 
				fg_color="#00000f", text_color="#00cccc", font=("Arial", 16))
			self.tituloopt6.grid(row=0, column=0, columnspan=4, padx=(343,0), pady=(3,0), sticky=("w"))
			"""
			"""
			self.tituloopt6=CTkLabel(master=self.opt6frame, text="Configuración", width=686, height=50,
				fg_color="#00000f", text_color="#00cccc", font=("Calibri", 32, "bold"))
			self.tituloopt6.grid(row=0, column=0, columnspan=6, padx=(10,0), pady=(3,0), sticky=(""))
			"""
			print("Configurando...")
			self.opt6frame.grid(row=1, column=0, rowspan=3, columnspan=4, padx=(3,0), pady=(2,0))

		#--------------------------------------------------------------------------OPT---------------------------------------------------------------------------#
		def buttonopt7(self):
			self.quitframes(6)
			self.opt7frame.grid_propagate(False)
			"""
			self.tituloopt7=CTkLabel(master=self.opt7frame, text="Perfil", width=686, height=50,
				fg_color="#00000f", text_color="#00cccc", font=("Calibri", 32, "bold"))
			self.tituloopt7.grid(row=0, column=0, columnspan=6, padx=(10,0), pady=(3,0), sticky=(""))

			self.fotouserl=CTkLabel(master=self.opt7frame, fg_color="#00000f", text="", image=self.img1c7)
			self.fotouserl.grid(row=1, column=0, padx=(10,0))

			nameuser=os.getlogin()
			self.nameuserl=CTkLabel(master=self.opt7frame, text=nameuser, width=200, height=50,
				fg_color="#00000f", text_color="#00cccc", font=("Calibri", 32, "bold"))
			self.nameuserl.grid(row=1, column=1, padx=(10,0), pady=(0,0), sticky=("w"))
			"""
			print("Perfil...")
			self.opt7frame.grid(row=1, column=0, rowspan=3, columnspan=4, padx=(3,0), pady=(2,0))

		#--------------------------------------------------------------------------OPT---------------------------------------------------------------------------#
		def buttonopt8(self):
			self.quitframes(7)
			self.opt8frame.grid_propagate(False)

			self.tituloopt8=CTkLabel(master=self.opt8frame, text="Acerca de Horux", width=686, height=50,
				fg_color="#00000f", text_color="#00cccc", font=("Calibri", 32))
			self.tituloopt8.grid(row=0, column=0, columnspan=6, padx=(10,0), pady=(3,0), sticky=(""))

			print("Informando...")
			self.textboxopt8=CTkTextbox(master=self.opt8frame, width=686, height=300, corner_radius=10, text_color="#00cccc", 
				border_width=1, border_color="#00cccc", bg_color="#00000f", fg_color="#00000f", scrollbar_button_color="#00cccc", scrollbar_button_hover_color="#00fff6", font=("Calibri", 16))
			self.textboxopt8.insert("0.0", "{}".format("    Copyright © 2024 Jesús A. Toro. Todos los derechos reservados. Horux {}\n\n    Horux, es un Software de Seguridad Informática Antivirus e Integral, que ofrece las siguientes\nfunciones para su sistema operativo.\n\nEscanear: Consiste en la búsqueda, identificación y eliminación de Virus informáticos alojados en su computador.\n\nLimpiador: Se trata de una simple función que elimina archivos temporales del ordenador.\n\nURL Checker: Facilita al usuario poder consultar una URL para determinar si es maliciosa.\n\nHistorial: Un registro de las operaciones realizadas por la función Antivirus.").format(self.version))
			self.textboxopt8.grid(row=2, column=0, rowspan=2, columnspan=4, sticky="ew", padx=(10,0), pady=(3,0))
			self.textboxopt8.configure(state="disabled")

			self.opt8frame.grid(row=1, column=0, rowspan=3, columnspan=4, padx=(3,0), pady=(2,0))

		#--------------------------------------------------------------------------MENUBAR---------------------------------------------------------------------------#
		#--------------------------------------------------------------------------MENUBAR---------------------------------------------------------------------------#
		#--------------------------------------------------------------------------MENUBAR---------------------------------------------------------------------------#
		def buttonhelpbar(self):
			#------------------------------------AVISOdE------------------------------------
			quitorden=False
			if self.subwinstts==True:
				self.subwinstts=False
				try:
					self.help.destroy()
				except:
					pass
				try:
					self.vista.destroy()
				except:
					pass
				try:
					self.tools.destroy()
				except:
					pass
				try:
					self.unbind("<Button-1>")
					self.unbind("<Button-2>")
					self.unbind("<Button-3>")
					self.unbind("<Configure>")
				except:
					pass
				quitorden=True
			elif self.subwinstts==False:
				#------------------------------------VENTANA------------------------------------
				self.help=CTkToplevel(self, fg_color="#131313")
				self.help.overrideredirect(True)
				self.help.grid_propagate(True)
				self.help.geometry("{}x{}+{}+{}".format("120","65",self.winfo_x()+136, self.winfo_y()+54))
				#self.help.transient(self)
				#self.help.wm_attributes('-topmost', False)
				#self.help.grab_set_global()
				#------------------------------------ELEMENTS-----------------------------------
				self.help1=CTkButton(master=self.help, text=" Manual de Usuario", command=lambda:print("Manual De Usuario"), 
					border_color="#2c2c2c", bg_color="#2c2c2c", fg_color="#2c2c2c", hover_color="#3c3c3c", height=20, width=120, anchor="w", corner_radius=0)
				self.help1.grid(row=0, column=0, sticky="we", padx=(1,1), pady=(1,0))
				
				self.help2=CTkButton(master=self.help, text=" Acerca de Horux", command=lambda:self.buttonopt8(), 
					border_color="#2c2c2c", bg_color="#2c2c2c", fg_color="#2c2c2c", hover_color="#3c3c3c", height=20, width=120, anchor="w", corner_radius=0)
				self.help2.grid(row=1, column=0, sticky="we", padx=(1,1), pady=(0,0))

				self.helpx=CTkButton(master=self.help, text="-", command=lambda:quithelpbar(1), 
					border_color="#2c2c2c", bg_color="#2c2c2c", fg_color="#2c2c2c", hover_color="#3c3c3c", height=20, width=120, corner_radius=0)
				self.helpx.grid(row=2, column=0, sticky="we", padx=(1,1), pady=(0,1))

				def quithelpbar(Evento):
					self.subwinstts=False
					self.help.destroy()
					self.unbind("<Button-1>")
					self.unbind("<Button-2>")
					self.unbind("<Button-3>")
					self.unbind("<Configure>")
					quitorden=True
					return quitorden
				def unclickmenubar(Evento):
					x, y=pyautogui.position()
					ypositioncursorwin=y-self.winfo_y()
					#print("Posición y: ", ypositioncursorwin)
					if ypositioncursorwin>=54:
						#LINUXIS28if ypositioncursorwin>=28:
						quithelpbar(1)
						
					return
				def FocoOut(Evento):
					quithelpbar(None)
					print("No primer plano. Cerrando")
				#------------------------------------EVENTOS------------------------------------
				self.bind("<Configure>", quithelpbar)
				self.bind("<Button-1>", unclickmenubar)
				self.bind("<Button-2>", unclickmenubar)
				self.bind("<Button-3>", unclickmenubar)

			if quitorden==True:
				self.subwinstts=False
				return
			self.subwinstts=True

		def buttonvistabar(self):
			#------------------------------------AVISOdE------------------------------------
			quitorden=False
			if self.subwinstts==True:
				self.subwinstts=False
				try:
					self.help.destroy()
				except:
					pass
				try:
					self.vista.destroy()
				except:
					pass
				try:
					self.tools.destroy()
				except:
					pass
				try:
					self.unbind("<Button-1>")
					self.unbind("<Button-2>")
					self.unbind("<Button-3>")
					#self.unbind("<FocusOut>")
					self.unbind("<Configure>")
				except:
					pass
				#self.update()
				quitorden=True
			elif self.subwinstts==False:
				#------------------------------------VENTANA------------------------------------
				self.vista=CTkToplevel(self, fg_color="#131313")
				self.vista.overrideredirect(True)
				self.vista.grid_propagate(False)
				self.vista.geometry("{}x{}+{}+{}".format("120","40",self.winfo_x()+74, self.winfo_y()+54))
				self.vista.transient(self)
				#self.vista.wm_attributes('-topmost', False)
				#------------------------------------ELEMENTS-----------------------------------
				self.vista1=CTkButton(master=self.vista, text=" Minimizar", command=lambda:self.iconify(), 
					border_color="#2c2c2c", bg_color="#2c2c2c", fg_color="#2c2c2c", hover_color="#3c3c3c", height=20, width=120, anchor="w", corner_radius=0)
				self.vista1.grid(row=0, column=0, sticky="we", padx=(1,1), pady=(1,0))

				self.vistax=CTkButton(master=self.vista, text="-", command=lambda:quitvistabar(1), 
					border_color="#2c2c2c", bg_color="#2c2c2c", fg_color="#2c2c2c", hover_color="#3c3c3c", height=20, width=120, corner_radius=0)
				self.vistax.grid(row=1, column=0, sticky="we", padx=(1,1), pady=(0,1))

				def quitvistabar(Evento):
					self.subwinstts=False
					self.vista.destroy()
					self.unbind("<Button-1>")
					self.unbind("<Button-2>")
					self.unbind("<Button-3>")
					self.unbind("<Configure>")
					quitorden=True
					return quitorden
				def unclickvistabar(Evento):
					x, y=pyautogui.position()
					ypositioncursorwin=y-self.winfo_y()

					if ypositioncursorwin>=54:
						quitvistabar(None)
					return

				#------------------------------------EVENTOS------------------------------------
				
				self.bind("<Configure>", quitvistabar)
				self.bind("<Button-1>", unclickvistabar)
				self.bind("<Button-2>", unclickvistabar)
				self.bind("<Button-3>", unclickvistabar)

				

				#self.vista.bind("<FocusOut>", FocoOut)
				#<<FocusOut>> lambda event: self.vista.destroy()

			if quitorden==True:
				self.subwinstts=False
				return
			self.subwinstts=True

		def buttontoolsbar(self):
			quitorden=False
			if self.subwinstts==True:
				self.subwinstts=False
				try:
					self.help.destroy()
				except:
					pass
				try:
					self.vista.destroy()
				except:
					pass
				try:
					self.tools.destroy()
				except:
					pass
				try:
					self.unbind("<Button-1>")
					self.unbind("<Button-2>")
					self.unbind("<Button-3>")
					self.unbind("<Configure>")
				except:
					pass
				quitorden=True
			elif self.subwinstts==False:
				#------------------------------------VENTANA------------------------------------
				self.tools=CTkToplevel(self, fg_color="#131313")
				self.tools.overrideredirect(True)
				self.tools.grid_propagate(False)
				self.tools.geometry("{}x{}+{}+{}".format("120","40",self.winfo_x()+8, self.winfo_y()+54))
				self.tools.transient(self)
				#------------------------------------ELEMENTS-----------------------------------
				self.tools1=CTkButton(master=self.tools, text=" Registro          Ctrl+'", command=lambda:print("Registro"), 
					border_color="#2c2c2c", bg_color="#2c2c2c", fg_color="#2c2c2c", hover_color="#3c3c3c", height=20, width=120, anchor="w", corner_radius=0)
				self.tools1.grid(row=0, column=0, sticky="we", padx=(1,1), pady=(1,0))
				
				self.toolsx=CTkButton(master=self.tools, text="-", command=lambda:quittoolsbar(1), 
					border_color="#2c2c2c", bg_color="#2c2c2c", fg_color="#2c2c2c", hover_color="#3c3c3c", height=20, width=120, corner_radius=0)
				self.toolsx.grid(row=1, column=0, sticky="we", padx=(1,1), pady=(0,1))

				def quittoolsbar(Evento):
					self.subwinstts=False
					self.tools.destroy()
					self.unbind("<Button-1>")
					self.unbind("<Button-2>")
					self.unbind("<Button-3>")
					self.unbind("<Configure>")
					quitorden=True
					return quitorden
				def unclicktoolsbar(Evento):
					x, y=pyautogui.position()
					ypositioncursorwin=y-self.winfo_y()
					if ypositioncursorwin>=54:
						quittoolsbar(1)
					return

				#------------------------------------EVENTOS------------------------------------
				self.bind("<Configure>", quittoolsbar)
				self.bind("<Button-1>", unclicktoolsbar)
				self.bind("<Button-2>", unclicktoolsbar)
				self.bind("<Button-3>", unclicktoolsbar)

			if quitorden==True:
				self.subwinstts=False
				return
			self.subwinstts=True


		#----------------------------------DatosdelaVentana----------------------------------#
		def datawin(self):
			self.pw1=self.winfo_screenwidth()
			self.ph1=self.winfo_screenheight()
			self.ph2=512
			self.pw2=912
			self.ubix=round(self.pw1/2-self.pw2/2)
			self.ubiy=round(self.ph1/2-(self.ph2/2+32))
			self.geometrytxt="{}x{}+{}+{}".format(self.pw2,self.ph2,self.ubix,self.ubiy)

	app=App()
	print("Post App() -l 1168")
	app.mainloop()
