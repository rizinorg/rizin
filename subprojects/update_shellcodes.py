from pathlib  import Path
import os
import shutil
import subprocess


GITLAB_REPO = "https://gitlab.com/exploit-database/exploitdb.git"
CLONE_DIR = "exploitdb"
OUTPUT_DIR = "rizin_shellcodes"
SHELLCODE_DIR = f"{CLONE_DIR}/shellcodes"

def run(cmd, cwd=None):
    return subprocess.run(cmd, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def git_clone_or_pull():
    if not os.path.exists(CLONE_DIR):
        print("[*] Cloning Gitlab ExploitDB...")
        run(f"git clone {GITLAB_REPO}")
    else:
        print("[*] Pulling latest from Gitlab...")
        run("git pull", cwd=CLONE_DIR)



def find_asm_files():
    return list(Path(SHELLCODE_DIR).rglob("*.nasm")) + list(Path(SHELLCODE_DIR).rglob("*.asm"))
    
def assemble_shellcode(asm_file: Path, tmp_dir: Path):
    base = asm_file.stem
    obj = tmp_dir / f"{base}.o"
    binfile = tmp_dir / f"{base}.bin"
    rawfile = tmp_dir / f"{base}.raw"

    arch_flag = "-f elf32" if "x86" in asm_file.parts else "-f elf"

    res = run(f"nasm {arch_flag} '{asm_file}' -o '{obj}")
    if res.returncode != 0:
        print(f"[!] NASM failed: {asm_file.name}")
        return None

    run(f"ld -m elf_i386 -o '{binfile}' '{obj}'")

    run(f"objcopy -O binary '{binfile}' '{rawfile}'")
    if not rawfile.exists():
        return None
    
    return rawfile.read_bytes()

def write_sc(path: Path, name: str, arch: str, hexdata: bytes):
    with open(path, 'w') as f:
        f.write(f"name={name}\n")
        f.write(f"arch={arch}\n")
        f.write(f"os=linux\n")
        f.write(f"bytes={hexdata.hex()}\n")

def update_shellcodes():
    tmp = Path("/tmp/rzsc_gitlab")
    if tmp.exists(): shutil.rmtree(tmp)
    tmp.mkdir()

    if os.path.exists(OUTPUT_DIR): shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR)

    git_clone_or_pull()

    asm_files = find_asm_files()

    print(f"[*] Found {len(asm_files)} shellcodes.")

    for asm in asm_files:
        arch = asm.parts[2]
        name = asm.stem
        data = assemble_shellcode(asm, tmp)
        if data is None:
            continue

        out_dir = Path(OUTPUT_DIR) / arch
        out_dir.mkdir(parents=True, exists_ok=True)
        out_path = out_dir / f"{name}.sc"
        write_sc(out_path, name, arch, data)
        print(f"[+] Saved: {out_path}")

    shutil.rmtree(tmp)
    print(f"Done! Shellcodes saved in {OUTPUT_DIR}")
    

if __name__ == "__main__":
    update_shellcodes()