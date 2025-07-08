
<h1 align="center">CTkFileDialog</h1>

<h3 align="center">A modern and fully customizable File Dialog for CustomTkinter — a must-have extension pack!</h3>

> **⚠️ Warning:**  
> This project is currently only supported on **Linux**. It has **not yet been tested on Windows**.
> Unfortunately parameters like video_preview or preview_img, and tooltip are not compatible with the mini dialog and will not be applied.

---

## 🚀 Features

- 🔍 Autocomplete in the path entry field (with `Tab`, `Up`, and `Down`)
- 🖼️ Live image preview
- 🎥 Video thumbnail preview
- 📁 Directory selection
- 💾 Save file dialog (return path or open file)

---

## 📦 Installation

```bash

git clone https://github.com/FlickGMD/CTkFileDialog
cd CTkFileDialog
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt

# Or ussing pip 

python3 -m venv .venv 
source .venv/bin/activate 
pip3 install CTkFileDialog 

```

---

## 🧪 Demo — All Methods

### 🗂️ Open File

```python
import customtkinter as ctk
from CTkFileDialog import askopenfilename

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

def open_file():
    path = askopenfilename(preview_img=True, autocomplete=True)
    if path:
        result_label.configure(text=f"Selected file:\n{path}")

app = ctk.CTk()
app.title("askopenfilename Demo")
app.geometry("500x200")

ctk.CTkButton(app, text="Open File", command=open_file).pack(pady=20)
result_label = ctk.CTkLabel(app, text="Waiting for file selection...")
result_label.pack()

app.mainloop()
```

---

### 🗂️ Open Multiple Files


```python
import customtkinter as ctk
from CTkFileDialog import askopenfilenames

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

def open_files():
    paths = askopenfilenames(preview_img=True, autocomplete=True)
    if paths:
        result_label.configure(text="Selected files:\n" + "\n".join(paths))

app = ctk.CTk()
app.title("askopenfilenames Demo")
app.geometry("500x300")

ctk.CTkButton(app, text="Open Multiple Files", command=open_files).pack(pady=20)
result_label = ctk.CTkLabel(app, text="Waiting for file selection...", wraplength=450)
result_label.pack()

app.mainloop()
```

---

### 📁 Select Directory

```python
import customtkinter as ctk
from CTkFileDialog import askdirectory

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

def select_directory():
    folder = askdirectory(autocomplete=True)
    if folder:
        result_label.configure(text=f"Selected directory:\n{folder}")

app = ctk.CTk()
app.title("askdirectory Demo")
app.geometry("500x200")

ctk.CTkButton(app, text="Select Directory", command=select_directory).pack(pady=20)
result_label = ctk.CTkLabel(app, text="Waiting for directory selection...")
result_label.pack()

app.mainloop()
```

---

### 💾 Save As (get path only)

```python
import customtkinter as ctk
from CTkFileDialog import asksaveasfilename

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

def save_as_filename():
    path = asksaveasfilename(autocomplete=True)
    if path:
        result_label.configure(text=f"Save file as:\n{path}")

app = ctk.CTk()
app.title("asksaveasfilename Demo")
app.geometry("500x200")

ctk.CTkButton(app, text="Save As (Filename Only)", command=save_as_filename).pack(pady=20)
result_label = ctk.CTkLabel(app, text="Waiting for filename...")
result_label.pack()

app.mainloop()
```

---

### 💾 Save As (write to file)

```python
import customtkinter as ctk
from CTkFileDialog import asksaveasfile

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

def save_as_file():
    file = asksaveasfile(autocomplete=True)
    if file:
        file.write("This file was created using the demo.")
        file.close()
        result_label.configure(text=f"File saved:\n{file.name}")

app = ctk.CTk()
app.title("asksaveasfile Demo")
app.geometry("500x200")

ctk.CTkButton(app, text="Save As (Real File)", command=save_as_file).pack(pady=20)
result_label = ctk.CTkLabel(app, text="Waiting for save location...")
result_label.pack()

app.mainloop()
```
---

## 🧩 Parameters

<div align="center">

| Parameter       | Description                                                                 |
|----------------|-----------------------------------------------------------------------------|
| `hidden`        | Show hidden files or directories (`False` by default).                     |
| `preview_img`   | Enable image preview in the file dialog.                                   |
| `video_preview` | Show first frame of video files as thumbnail (experimental).               |
| `autocomplete`  | Enable path autocompletion with `Tab`, `Up`, and `Down`.                   |
| `initial_dir`   | Set the initial directory when opening the dialog.                         |
| `tool_tip`   | Enable the tool tip.                         |
| `style`   | Defines the dialog style, by default it will be 'Default' but you can choose a small one ('Mini')                        |

</div>

---

## 🌙 Dark Mode Preview

<p align="center">
  <img src="./Images/NormalDialogDark.png" width="80%">
</p>

## ☀️ Light Mode Preview

<p align="center">
  <img src="./Images/NormalDialogLight.png" width="80%">
</p>

---

## Package constants 

This module has constants that can be used outside or inside the dialog, they are used to obtain paths like /home/user or /home/user/.config/
Here is a basic example

```python3 
#!/usr/bin/env python3 
import customtkinter as ctk 
from CTkFileDialog import askopenfilename
from CTkFileDialog.Constants import HOME

root = ctk.CTk()

def open_file(): 
    f = askopenfilename(initial_dir=HOME, autocomplete=True)
    if f: 
        print(f"file selected: {f}")

ctk.CTkButton(master=root, command=open_file, text="Open File").pack(padx=10, pady=10, anchor=ctk.CENTER)

root.mainloop()
```

--- 

## Mini Dialog 

This is a parameter of the file dialog, but it's more powerful than the default one. As I mentioned earlier, it doesn't support parameters like tooltip, preview_img, or video_preview.

## 🌙 Dark Mode Preview

<p align="center">
  <img src="./Images/MiniDialogDark.png" width="80%">
</p>

## ☀️ Light Mode Preview

<p align="center">
  <img src="./Images/MiniDialogLight.png" width="80%">
</p>

The mini design wasn't created by me; it was created by this user, and all credit goes to him. I also want to thank him for creating that design in advance.

---

## 👨‍💻 Under Development

This tool is actively under development.  
If you have any ideas, bugs, or requests — feel free to contribute!

---

## 🔗 Repository

👉 [GitHub Repo](https://github.com/FlickGMD/CTkFileDialog)

<h2 align="center"> This tool is under development, I hope you like it! </h2>

