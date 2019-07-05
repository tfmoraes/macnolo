import functools
import glob
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


CACHE_FOLDER = pathlib.Path(".cache")
CACHE_FOLDER.mkdir(parents=True, exist_ok=True)

launcher_template = Template(
    """
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> /* for fork */
#include <sys/types.h> /* for pid_t */
#include <sys/wait.h> /* for wait */
#include <string.h>
#include <libgen.h>

int main(int argc, char** argv)
{
    /*Spawn a child to run the program.*/
    pid_t pid=fork();
    if (pid==0) { /* child process */
        char cwd[1024];
        char* dname = dirname(argv[0]);
        strcpy(cwd, dname);
        strcat(cwd, "/$script_folder");
        chdir(cwd);
        printf("Current working dir: %s\\n", cwd);
        static char *argv[]={"python3", "$script_name", NULL};
        execv("../libs/bin/python3", argv);
        exit(127); /* only if execv fails */
    }
    else { /* pid!=0; parent process */
        waitpid(pid,0,0); /* wait for child to exit */
    }
    return 0;
}
"""
)


def run_cmd(cmd):
    with subprocess.Popen(
        cmd, stdout=subprocess.PIPE, bufsize=1, universal_newlines=True
    ) as p:
        for line in p.stdout:
            print(line, end="")

    if p.returncode != 0:
        raise subprocess.CalledProcessError(p.returncode, p.args)


def download_and_install_pip(python_exec):
    print("Downloading and installing pip")
    pip_path = download_and_check("https://bootstrap.pypa.io/get-pip.py")
    run_cmd([str(python_exec), str(pip_path)])


def pip_install(python_exec, pip_package):
    print("Installing", pip_package)
    run_cmd([str(python_exec), "-m", "pip", "install", pip_package])


def calc_hash(filename):
    with open(filename, "r+b") as f:
        h = hashlib.sha256(f.read())
        return h.hexdigest()


def relative_to(path, rel):
    path = pathlib.Path(path)
    return os.path.relpath(str(path.parent), str(rel)) + "/" + path.parts[-1]


def download_and_check(url, sha=None):
    filename = url.split("/")[-1]
    filepath = CACHE_FOLDER.joinpath(filename)
    if filepath.exists():
        if sha is None or calc_hash(filepath) == sha:
            print("Already downloaded")
            return filepath
        else:
            print("Sha256 doesn't match downloading again.")

    with open(filepath, "w+b") as f:
        r = request.urlopen(url)
        for bits in r:
            f.write(bits)
    return filepath


def extract_files(filename, dest, skip_path=2):
    print("Extracting", filename)
    extracted_files = []
    with tarfile.open(filename) as tf:
        for ti in tf:
            dest_name = dest.joinpath("/".join(ti.name.split("/")[skip_path:]))
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
        "CFBundleIconFile": icon,
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
    print("\t", c_temp_file)
    with open(c_temp_file, "w") as f:
        f.write(
            launcher_template.substitute(
                script_path=script_path,
                script_folder=relative_to(script_path.parent, exec_file.parent),
                script_name=script_path.name,
            )
        )
    print("Compiling launcher")
    run_cmd(["clang", c_temp_file, "-o", exec_file])


def main():
    json_fname = pathlib.Path(sys.argv[1])
    base_path = json_fname.parent
    with open(json_fname) as json_input:
        dict_json = json.load(json_input)

    app_name = dict_json["app_name"]
    version = dict_json["version"]
    icon = dict_json["icon"]
    packages = dict_json["packages"]
    ignore_packages = dict_json["ignore_packages"]
    pip_packages = dict_json["pip_packages"]
    mac_version = dict_json["mac_version"]
    package_type = dict_json["app_package"]["type"]
    if package_type == package_type:
        package_path = base_path.joinpath(dict_json["app_package"]["path"])
    else:
        package_url = dict_json["app_package"]["url"]
        package_path = download_and_check(package_url)
    start_script = dict_json["app_package"]["start_script"]
    exclude_files = dict_json["exclude_files"]

    # Creating folders
    app_folder = pathlib.Path(app_name + ".app")
    app_folder.mkdir(parents=True, exist_ok=True)

    resources_folder = app_folder.joinpath("Contents/Resources")
    resources_folder.mkdir(parents=True, exist_ok=True)

    binary_folder = app_folder.joinpath("Contents/MacOS")
    binary_folder.mkdir(parents=True, exist_ok=True)

    libs_folder = resources_folder.joinpath("libs")
    libs_folder.mkdir(parents=True, exist_ok=True)

    application_folder = resources_folder.joinpath("app")
    application_folder.mkdir(parents=True, exist_ok=True)

    # Copying icon in the package
    shutil.copy2(base_path.joinpath(icon), resources_folder)

    # Creating Info.plist file
    create_app_info(app_folder, app_name, version, icon)

    # Copying or extracting app files inside the package
    if package_type == "file":
        shutil.copy2(package_path, str(application_folder))
    else:
        extract_files(package_path, application_folder)

    create_launcher(app_folder, application_folder.joinpath(start_script))

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
        link_site_packages = libs_folder.joinpath(
            "Frameworks/Python.framework/Versions/3.7/lib/python3.7/site-packages"
        )
        os.symlink(
            relative_to(site_packages, link_site_packages.parent), link_site_packages
        )

    path_by_file = {}
    for extracted_file in extracted_files:
        path_by_file["/".join(extracted_file.parts[-2:])] = extracted_file

    def change_func(path):
        new_path = path_by_file.get("/".join(path.split("/")[-2:]), path)
        if path == new_path:
            return path
        return "@loader_path/" + relative_to(new_path, package_file.parent)

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
                print("rewriting", package_file)
                # Making the file writable
                st_mode = package_file.stat().st_mode
                package_file.chmod(st_mode | stat.S_IWUSR)
                with package_file.open("rb+") as f:
                    f.seek(0)
                    macho.write(f)
                package_file.chmod(st_mode)

    # Installing python packages using pip
    PYTHON_EXEC = libs_folder.joinpath("bin/python3")
    download_and_install_pip(PYTHON_EXEC)
    for pip_package in pip_packages:
        pip_install(PYTHON_EXEC, pip_package)

    # Excluding files marked to exclusion by user
    print("Removing files")
    for exclude_file in exclude_files:
        if glob.has_magic(exclude_file):
            for ff in resources_folder.glob("**/{}".format(exclude_file)):
                print("\tremoving", ff)
                if ff.is_dir():
                    shutil.rmtree(str(ff), ignore_errors=True)
                else:
                    ff.unlink()
        else:
            ff = resources_folder.joinpath(exclude_file)
            print("\tremoving", ff)
            if ff.is_dir():
                shutil.rmtree(str(ff), ignore_errors=True)
            else:
                ff.unlink()

if __name__ == "__main__":
    main()
