import hashlib
import json
import pathlib
import shutil
import sys
import tarfile
from urllib import request
import plistlib
import subprocess

from macholib import MachO

CACHE_FOLDER = pathlib.Path(".cache")
CACHE_FOLDER.mkdir(parents=True, exist_ok=True)


def calc_hash(filename):
    with open(filename, "r+b") as f:
        h = hashlib.sha256(f.read())
        return h.hexdigest()


def relative_to(path, rel):
    parts = path.parts
    return pathlib.Path('@executable_path/..').joinpath('/'.join(parts[2:]))


def get_shared_lib_deps(shared_lib_filename):
    output = subprocess.check_output(("otool", "-L", str(shared_lib_filename)))
    libs = output.split(b'\n')
    return [i.strip().split()[0].decode('utf8') for i in libs if i.startswith(b'\t')]


def change_libs_path(lib, old_path, new_path):
    output = subprocess.check_output(("install_name_tool", "-change", old_path, new_path, lib))
    print(output)


def download_and_check(url, sha):
    filename = url.split("/")[-1]
    filepath = CACHE_FOLDER.joinpath(filename)
    if filepath.exists():
        if calc_hash(filepath) == sha:
            print("Already downloaded")
            return filepath
        else:
            print("Sha256 doesn't match downloading again.")

    with open(filepath, "w+b") as f:
        r = request.urlopen(url)
        for bits in r:
            f.write(bits)
    return filepath


def extract_files(filename, dest):
    print("Extracting", filename)
    extracted_files = []
    with tarfile.open(filename) as tf:
        for ti in tf:
            dest_name = dest.joinpath('/'.join(ti.name.split("/")[2:]))
            if ti.isdir():
                dest_name.mkdir(parents=True, exist_ok=True)
            tf._extract_member(ti, str(dest_name), False)
            extracted_files.append(dest_name)
    return extracted_files


def create_app_info(app_folder, app_name, version, icon):
    print("Generating info.plist")
    info = {
        "CFBundlePackageType": "APPL",
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleIconFile": "icon.icns",
        "CFBundleName": app_name,
        "CFBundleExecutable": "run.sh",
        "CFBundleIdentifier": app_name,
        "CFBundleVersion": version,
        "CFBundleGetInfoString": "123",
        "CFBundleShortVersionString": version,
        "NSPrincipalClass": "NSApplication",
        "NSMainNibFile": "MainMenu"
    }
    info_path = app_folder.joinpath("Contents/Info.plist")
    with info_path.open('wb') as fp:
        plistlib.dump(info, fp)


def create_script_launcher(app_folder):
    exec_file = app_folder.joinpath("Contents/MacOS/run.sh")
    with exec_file.open("w") as f:
        f.write(
"""#!/usr/bin/env bash
cd "$(dirname "$0")"
echo "Manolo" > /tmp/test.txt
../Resources/libs/bin/python3 teste.py
""")
    exec_file.chmod(0o777)


def main():
    json_fname = sys.argv[1]
    with open(json_fname) as json_input:
        dict_json = json.load(json_input)

    app_name = dict_json["app_name"]
    version = dict_json["version"]
    packages = dict_json["packages"]
    ignore_packages = dict_json["ignore_packages"]
    mac_version = dict_json["mac_version"]

    app_folder = pathlib.Path(app_name + '.app')
    libs_folder = app_folder.joinpath("Contents/Resources/libs/")
    libs_folder.mkdir(parents=True, exist_ok=True)

    binary_folder = app_folder.joinpath("Contents/MacOS")
    binary_folder.mkdir(parents=True, exist_ok=True)

    create_app_info(app_folder, app_name, version, "manolo.icsn")
    create_script_launcher(app_folder)

    shutil.copy2("teste.py", str(binary_folder))

    downloaded = []
    package_files = []
    while packages:
        package = packages.pop(0)
        print(
            "package", package, f"https://formulae.brew.sh/api/formula/{package}.json"
        )
        r = request.urlopen(f"https://formulae.brew.sh/api/formula/{package}.json")
        package_info = json.load(r)
        dependencies = package_info["dependencies"]
        bottle_url = package_info["bottle"]["stable"]["files"][mac_version]["url"]
        bottle_hash = package_info["bottle"]["stable"]["files"][mac_version]["sha256"]
        package_files.append(download_and_check(bottle_url, bottle_hash))
        for dependency in dependencies:
            if dependency not in ignore_packages and dependency not in packages and dependency not in downloaded:
                packages.append(dependency)
        downloaded.append(package)

    extracted_files = []
    for package in package_files:
        extracted_files.extend(extract_files(package, libs_folder))

    path_by_file = {}
    for extracted_file in extracted_files:
        path_by_file['/'.join(extracted_file.parts[-2:])] = relative_to(extracted_file, '')

    def change_func(path):
        filename = '/'.join(path.split("/")[-2:])
        return str(path_by_file.get(filename, path))

    for package_file in extracted_files:
        extension = package_file.suffixes
        if package_file.is_file():
            try:
                # print(package_file)
                macho = MachO.MachO(str(package_file))
            except Exception:
                # Not lib
                continue
            rewrote = False
            for header in macho.headers:
                if macho.rewriteLoadCommands(change_func):
                    rewrote = True
            
            if rewrote:
                print("rewrite", package_file)
                with package_file.open("rb+") as f:
                    f.seek(0)
                    macho.write(f)

if __name__ == "__main__":
    main()
