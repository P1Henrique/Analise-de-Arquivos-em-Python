import tkinter as tk
from tkinter import ttk, filedialog
import os
import datetime
import mimetypes
import chardet
import hashlib
import stat

class FileAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Analisador de Arquivos")
        self.root.geometry("600x450")
        
        # Configurar tema escuro
        self.set_dark_theme()
        
        # Área principal
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Área de seleção
        select_frame = ttk.Frame(main_frame, padding="20")
        select_frame.pack(fill=tk.X, padx=10, pady=10)
        
        select_label = ttk.Label(select_frame, text="Selecione um arquivo para análise:")
        select_label.pack(anchor="w", pady=5)
        
        select_button = ttk.Button(select_frame, text="Selecionar Arquivo", 
                                  command=self.select_file)
        select_button.pack(fill=tk.X, pady=5)
        
        # Área de informações
        info_frame = ttk.LabelFrame(main_frame, text="Informações do Arquivo", padding="10")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Criar canvas com scrollbar para as informações
        canvas = tk.Canvas(info_frame, bg="#333333", highlightthickness=0)
        scrollbar = ttk.Scrollbar(info_frame, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Labels para informações básicas
        self.nome_label = ttk.Label(self.scrollable_frame, text="Nome: ")
        self.nome_label.pack(anchor="w", pady=2)
        
        self.caminho_label = ttk.Label(self.scrollable_frame, text="Caminho: ")
        self.caminho_label.pack(anchor="w", pady=2)
        
        self.tamanho_label = ttk.Label(self.scrollable_frame, text="Tamanho: ")
        self.tamanho_label.pack(anchor="w", pady=2)
        
        self.data_criacao_label = ttk.Label(self.scrollable_frame, text="Data de criação: ")
        self.data_criacao_label.pack(anchor="w", pady=2)
        
        self.data_mod_label = ttk.Label(self.scrollable_frame, text="Data de modificação: ")
        self.data_mod_label.pack(anchor="w", pady=2)
        
        self.data_acesso_label = ttk.Label(self.scrollable_frame, text="Último acesso: ")
        self.data_acesso_label.pack(anchor="w", pady=2)
        
        self.tipo_label = ttk.Label(self.scrollable_frame, text="Tipo: ")
        self.tipo_label.pack(anchor="w", pady=2)
        
        self.extensao_label = ttk.Label(self.scrollable_frame, text="Extensão: ")
        self.extensao_label.pack(anchor="w", pady=2)
        
        self.encoding_label = ttk.Label(self.scrollable_frame, text="Encodação: ")
        self.encoding_label.pack(anchor="w", pady=2)
        
        self.md5_label = ttk.Label(self.scrollable_frame, text="MD5 Hash: ")
        self.md5_label.pack(anchor="w", pady=2)
        
        self.permissoes_label = ttk.Label(self.scrollable_frame, text="Permissões: ")
        self.permissoes_label.pack(anchor="w", pady=2)
        
        self.oculto_label = ttk.Label(self.scrollable_frame, text="Arquivo oculto: ")
        self.oculto_label.pack(anchor="w", pady=2)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Pronto. Selecione um arquivo para analisar.")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def set_dark_theme(self):
        """Configurar tema escuro para a aplicação"""
        self.root.configure(bg="#333333")
        
        style = ttk.Style()
        style.theme_use("clam")  # Usar tema clam como base
        
        # Configurar cores para os widgets
        style.configure("TFrame", background="#333333")
        style.configure("TLabelframe", background="#333333", foreground="#FFFFFF")
        style.configure("TLabelframe.Label", background="#333333", foreground="#FFFFFF")
        style.configure("TLabel", background="#333333", foreground="#FFFFFF")
        style.configure("TButton", background="#555555", foreground="#FFFFFF")
        style.map("TButton",
                 background=[("active", "#666666"), ("pressed", "#444444")],
                 foreground=[("active", "#FFFFFF")])
        style.configure("TSeparator", background="#555555")
        style.configure("TScrollbar", background="#555555", arrowcolor="#FFFFFF", bordercolor="#555555")
        style.map("TScrollbar",
                 background=[("active", "#666666"), ("pressed", "#444444")])

    def select_file(self):
        """Abrir seletor de arquivo e analisar o arquivo selecionado"""
        filepath = filedialog.askopenfilename(
            title="Selecione um arquivo para analisar",
            filetypes=[("Todos os arquivos", "*.*")]
        )
        if filepath:
            self.status_var.set(f"Analisando: {os.path.basename(filepath)}")
            self.root.update_idletasks()
            self.analyze_file(filepath)
            self.status_var.set("Análise concluída.")

    def analyze_file(self, filepath):
        """Analisar o arquivo e exibir informações"""
        try:
            # Obter informações básicas
            file_stat = os.stat(filepath)
            file_name = os.path.basename(filepath)
            file_path = os.path.abspath(filepath)
            file_size = file_stat.st_size
            
            # Obter datas
            modified_time = datetime.datetime.fromtimestamp(file_stat.st_mtime)
            access_time = datetime.datetime.fromtimestamp(file_stat.st_atime)
            
            # No Windows, st_ctime é a data de criação, em UNIX é a data da última alteração de metadata
            creation_time = datetime.datetime.fromtimestamp(file_stat.st_ctime)
            
            # Determinar extensão e tipo de arquivo
            file_extension = os.path.splitext(filepath)[1]
            mimetype, _ = mimetypes.guess_type(filepath)
            if not mimetype:
                mimetype = "Desconhecido"
            
            # Verificar se é arquivo oculto
            is_hidden = False
            if os.name == 'nt':  # Windows
                import win32api, win32con
                try:
                    attribute = win32api.GetFileAttributes(filepath)
                    is_hidden = (attribute & win32con.FILE_ATTRIBUTE_HIDDEN)
                except:
                    is_hidden = "Não foi possível determinar"
            else:  # Unix/Linux/Mac
                is_hidden = os.path.basename(filepath).startswith('.')
                
            # Permissões do arquivo
            permissions = ""
            if os.name == 'posix':  # Unix/Linux/Mac
                mode = file_stat.st_mode
                permissions = stat.filemode(mode)
            else:  # Windows
                permissions = "r" if os.access(filepath, os.R_OK) else "-"
                permissions += "w" if os.access(filepath, os.W_OK) else "-"
                permissions += "x" if os.access(filepath, os.X_OK) else "-"
                
            # Detectar codificação
            encoding = "Desconhecido"
            try:
                with open(filepath, 'rb') as f:
                    result = chardet.detect(f.read(1024 * 1024))  # Ler até 1MB para detectar codificação
                    if result and result['confidence'] > 0.7:
                        encoding = f"{result['encoding']} (confiança: {result['confidence']:.2f})"
            except:
                encoding = "Não detectado"
            
            # Calcular hash MD5
            md5_hash = "Calculando..."
            self.md5_label.config(text=f"MD5 Hash: {md5_hash}")
            self.root.update_idletasks()
            
            try:
                md5_hash = self.calculate_md5(filepath)
            except:
                md5_hash = "Erro ao calcular"
            
            # Formatar tamanho do arquivo
            if file_size < 1024:
                size_str = f"{file_size} bytes"
            elif file_size < 1024 * 1024:
                size_str = f"{file_size/1024:.2f} KB ({file_size} bytes)"
            else:
                size_str = f"{file_size/(1024*1024):.2f} MB ({file_size} bytes)"
                
            # Atualizar labels
            self.nome_label.config(text=f"Nome: {file_name}")
            self.caminho_label.config(text=f"Caminho: {file_path}")
            self.tamanho_label.config(text=f"Tamanho: {size_str}")
            self.data_criacao_label.config(text=f"Data de criação: {creation_time.strftime('%d/%m/%Y %H:%M:%S')}")
            self.data_mod_label.config(text=f"Data de modificação: {modified_time.strftime('%d/%m/%Y %H:%M:%S')}")
            self.data_acesso_label.config(text=f"Último acesso: {access_time.strftime('%d/%m/%Y %H:%M:%S')}")
            self.tipo_label.config(text=f"Tipo: {mimetype}")
            self.extensao_label.config(text=f"Extensão: {file_extension}")
            self.encoding_label.config(text=f"Encodação: {encoding}")
            self.md5_label.config(text=f"MD5 Hash: {md5_hash}")
            self.permissoes_label.config(text=f"Permissões: {permissions}")
            self.oculto_label.config(text=f"Arquivo oculto: {'Sim' if is_hidden else 'Não'}")
            
        except Exception as e:
            self.show_error(f"Erro ao analisar arquivo: {str(e)}")
    
    def calculate_md5(self, filepath):
        """Calcular o hash MD5 do arquivo"""
        md5_hash = hashlib.md5()
        with open(filepath, "rb") as f:
            # Ler em blocos para não sobrecarregar a memória com arquivos grandes
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()
    
    def show_error(self, message):
        """Exibir mensagem de erro"""
        from tkinter import messagebox
        messagebox.showerror("Erro", message)
        self.status_var.set("Erro durante a análise do arquivo.")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileAnalyzerApp(root)
    root.mainloop()