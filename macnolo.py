import functools
import hashlib
import json
import operator
import os
import pathlib
import plistlib
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from string import Template
from urllib import request

from macholib import MachO


def chmod(location, description):
    """chmod(location, description) --> None
    Change the access permissions of file, using a symbolic description
    of the mode, similar to the format of the shell command chmod.
    The format of description is
        * an optional letter in o, g, u, a (no letter means a)
        * an operator in +, -, =
        * a sequence of letters in r, w, x, or a single letter in o, g, u
    Example:
        chmod(myfile, "u+x")    # make the file executable for it's owner.
        chmod(myfile, "o-rwx")  # remove all permissions for all users not in the group. 
    See also the man page of chmod.
    """
    if chmod.regex is None:
        import re

        chmod.regex = re.compile(
            r"(?P<who>[uoga]?)(?P<op>[+\-=])(?P<value>[ugo]|[rwx]*)"
        )
    mo = chmod.regex.match(description)
    who, op, value = mo.group("who"), mo.group("op"), mo.group("value")
    if not who:
        who = "a"
    mode = os.stat(location)[stat.ST_MODE]
    if value in ("o", "g", "u"):
        mask = ors((stat_bit(who, z) for z in "rwx" if (mode & stat_bit(value, z))))
    else:
        mask = ors((stat_bit(who, z) for z in value))
    if op == "=":
        mode &= ~ors((stat_bit(who, z) for z in "rwx"))
    mode = (mode & ~mask) if (op == "-") else (mode | mask)
    os.chmod(location, mode)


chmod.regex = None
# Helper functions
def stat_bit(who, letter):
    if who == "a":
        return stat_bit("o", letter) | stat_bit("g", letter) | stat_bit("u", letter)
    return getattr(stat, "S_I%s%s" % (letter.upper(), stat_bit.prefix[who]))


stat_bit.prefix = dict(u="USR", g="GRP", o="OTH")


def ors(sequence, initial=0):
    return functools.reduce(operator.__or__, sequence, initial)


# Test code

CACHE_FOLDER = pathlib.Path(".cache")
CACHE_FOLDER.mkdir(parents=True, exist_ok=True)

launcher_template = Template(
    """
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> /* for fork */
#include <sys/types.h> /* for pid_t */
#include <sys/wait.h> /* for wait */

int main()
{
    /*Spawn a child to run the program.*/
    pid_t pid=fork();
    if (pid==0) { /* child process */
        static char *argv[]={"python3", "$script_path", NULL};
        execv("../Resources/libs/bin/python3", argv);
        exit(127); /* only if execv fails */
    }
    else { /* pid!=0; parent process */
        waitpid(pid,0,0); /* wait for child to exit */
    }
    return 0;
}
"""
)


def calc_hash(filename):
    with open(filename, "r+b") as f:
        h = hashlib.sha256(f.read())
        return h.hexdigest()


def relative_to(path, rel):
    path = pathlib.Path(path)
    return os.path.relpath(str(path.parent), str(rel)) + "/" + path.parts[-1]


def get_shared_lib_deps(shared_lib_filename):
    output = subprocess.check_output(("otool", "-L", str(shared_lib_filename)))
    libs = output.split(b"\n")
    return [i.strip().split()[0].decode("utf8") for i in libs if i.startswith(b"\t")]


def change_libs_path(lib, old_path, new_path):
    output = subprocess.check_output(
        ("install_name_tool", "-change", old_path, new_path, lib)
    )
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
            dest_name = dest.joinpath("/".join(ti.name.split("/")[2:]))
            if ti.isdir():
                dest_name.mkdir(parents=True, exist_ok=True)
            tf._extract_member(ti, str(dest_name), not ti.isdir())
            extracted_files.append(dest_name)
    return extracted_files


def create_app_info(app_folder, app_name, version, icon):
    print("Generating info.plist")
    info = {
        "CFBundlePackageType": "APPL",
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleIconFile": "icon.icns",
        "CFBundleName": app_name,
        "CFBundleExecutable": "run",
        "CFBundleIdentifier": app_name,
        "CFBundleVersion": version,
        "CFBundleGetInfoString": "123",
        "CFBundleShortVersionString": version,
        "NSPrincipalClass": "NSApplication",
        "NSMainNibFile": "MainMenu",
    }
    info_path = app_folder.joinpath("Contents/Info.plist")
    with info_path.open("wb") as fp:
        plistlib.dump(info, fp)


def create_launcher(app_folder, script_path):
    print("Creating lancher")
    exec_file = app_folder.joinpath("Contents/MacOS/run")
    c_temp_file = tempfile.mktemp(suffix=".c")
    with open(c_temp_file, "w") as f:
        f.write(launcher_template.substitute(script_path=script_path))
    print("Compiling launcher")
    print(subprocess.check_call(["clang", c_temp_file, "-o", exec_file]))


def main():
    json_fname = sys.argv[1]
    with open(json_fname) as json_input:
        dict_json = json.load(json_input)

    app_name = dict_json["app_name"]
    version = dict_json["version"]
    packages = dict_json["packages"]
    ignore_packages = dict_json["ignore_packages"]
    mac_version = dict_json["mac_version"]

    app_folder = pathlib.Path(app_name + ".app")
    libs_folder = app_folder.joinpath("Contents/Resources/libs/")
    libs_folder.mkdir(parents=True, exist_ok=True)

    binary_folder = app_folder.joinpath("Contents/MacOS")
    binary_folder.mkdir(parents=True, exist_ok=True)

    create_app_info(app_folder, app_name, version, "manolo.icsn")

    application_folder = app_folder.joinpath("Contents/Resources/app/")
    application_folder.mkdir(parents=True, exist_ok=True)

    shutil.copy2("teste.py", str(application_folder))

    create_launcher(
        app_folder, relative_to(application_folder.joinpath("teste.py"), binary_folder)
    )

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
            if (
                dependency not in ignore_packages
                and dependency not in packages
                and dependency not in downloaded
            ):
                packages.append(dependency)
        downloaded.append(package)

    extracted_files = []
    for package in package_files:
        extracted_files.extend(extract_files(package, libs_folder))

    if "python" in downloaded:
        site_packages = libs_folder.joinpath("lib/python3.7/site-packages")
        link_site_packages = libs_folder.joinpath("Frameworks/Python.framework/Versions/3.7/lib/python3.7/site-packages")
        os.symlink(relative_to(site_packages, link_site_packages.parent), link_site_packages)

    path_by_file = {}
    for extracted_file in extracted_files:
        path_by_file["/".join(extracted_file.parts[-3:])] = extracted_file

    def change_func(path):
        if path.startswith("@@HOMEBREW_CELLAR@@"):
            path = libs_folder.joinpath("/".join(path.split("/")[3:]))
            if str(package_file).endswith(".so") or str(package_file).endswith(
                ".dylib"
            ):
                return "@loader_path/" + relative_to(path, package_file.parent)
            else:
                return "@executable_path/" + relative_to(path, package_file.parent)
        else:
            return path

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
                # print("rewrite", package_file)
                chmod(str(package_file), "u+w")
                with package_file.open("rb+") as f:
                    f.seek(0)
                    macho.write(f)


if __name__ == "__main__":
    main()
