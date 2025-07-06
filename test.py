#!/usr/bin/env python
import customtkinter as ctk
import CTkFileDialog
from CTkFileDialog.Constants import HOME 

def open_mini_file() -> None:
    f = CTkFileDialog.askopenfilename(style='Mini', autocomplete=True, initial_dir='.')
    if f:
        print(f"[+] Selected file ->", f)

def open_normal_file() -> None:
    f = CTkFileDialog.askopenfilename(style='Default', autocomplete=True, initial_dir=HOME, tool_tip=True)
    if f:
        print(f"[+] Selected file ->", f)

def toggle_theme():
    current = theme_switch.get()
    if current == 1:
        ctk.set_appearance_mode("Dark")
    else:
        ctk.set_appearance_mode("Light")

def main() -> None:
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("green")

    app = ctk.CTk()
    app.geometry("500x300")
    app.title("Archivo Selector")

    frame = ctk.CTkFrame(master=app, corner_radius=15)
    frame.pack(padx=40, pady=40, fill="both", expand=True)

    label = ctk.CTkLabel(master=frame, text="Selecciona un archivo", font=("Arial", 18))
    label.pack(pady=(10, 20))

    btn = ctk.CTkButton(master=frame, command=open_normal_file, text='📂 Dialogo Completo')
    btn.pack(pady=10)

    btn2 = ctk.CTkButton(master=frame, command=open_mini_file, text='🗂️ Dialogo Mini')
    btn2.pack(pady=10)

    global theme_switch
    theme_switch = ctk.CTkSwitch(master=frame, text="Modo Oscuro", command=toggle_theme)
    theme_switch.select()  
    theme_switch.pack(pady=10, padx=10)

    app.mainloop()

if __name__ == "__main__":
    main()

