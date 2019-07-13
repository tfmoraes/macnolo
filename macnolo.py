#!/usr/bin/env python3

import functools
import glob
import hashlib
import json
import logging
import operator
import os
import pathlib
import plistlib
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from string import Template
from typing import List
from urllib import request

from macholib import MachO

level = logging.INFO
if os.environ.get("DEBUG", False):
    level = logging.DEBUG
logging.basicConfig(
    filename="/tmp/saida.log", filemode="w", format="%(message)s", level=level
)

CACHE_FOLDER = pathlib.Path.home().joinpath(".cache/macnolo/")
CACHE_FOLDER.mkdir(parents=True, exist_ok=True)


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, pathlib.PosixPath):
            return str(o)
        return json.JSONEncoder.default(self, o)


class SharedLibraryChanger:
    def __init__(self, package_file, path_by_file, libs_folder):
        self.package_file = package_file
        self.path_by_file = path_by_file
        self.libs_folder = libs_folder

    def __call__(self, path):
        package_file = self.package_file
        path_by_file = self.path_by_file
        libs_folder = self.libs_folder
        if path.startswith("@@HOMEBREW_CELLAR@@"):
            new_path = libs_folder.joinpath("/".join(path.split("/")[3:]))
            new_path = "@loader_path/" + relative_to(new_path, package_file.parent)
            logging.debug(f"{package_file}: {path} -> {new_path}")
            return new_path
        else:
            for new_path in path_by_file.get(path.split("/")[-1], [path]):
                if path == new_path:
                    logging.debug(f"{package_file}: {path} -> {new_path}")
                    return path
                elif new_path == str(package_file):
                    continue
                elif not str(new_path).endswith(".dylib") or not str(new_path).endswith(
                    ".so"
                ):
                    try:
                        m = MachO.MachO(str(new_path))
                    except Exception:
                        continue
                    if m.headers[0].filetype == "execute":
                        continue
                new_path = "@loader_path/" + relative_to(new_path, package_file.parent)
                logging.debug(f"{package_file}: {path} -> {new_path}")
                return new_path
            logging.debug(f"{package_file}: {path} -> {path}")
            return path


launcher_template = Template(
    """
#include <libgen.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include<unistd.h>  

#define SIZE_OUTPUT 24

int main(int argc, char **argv) {
    char cwd[1024];
    char* dname = dirname(argv[0]);
    strcpy(cwd, dname);
    strcat(cwd, "/$script_folder");
    chdir(cwd);
    printf("Inside: %s\\n", cwd);
    char cmd[2048];
    strcpy(cmd, "$python_exec ");
    strcat(cmd, "$script_name");
    char output[SIZE_OUTPUT];
    printf("Running: %s\\n", cmd);
    FILE *fp = popen(cmd, "r");

    if (fp == NULL){
        fprintf(stderr, "could not run.\\n");
        return EXIT_FAILURE;
    }

    while(fgets(output, SIZE_OUTPUT, fp) != NULL) {
        printf("%s", output);
    }

    if (pclose(fp) != 0){
        fprintf(stderr, "could not run.\\n");
    }
    return EXIT_SUCCESS;
}
"""
)


def run_cmd(cmd, env=None, cwd=None):
    with subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        bufsize=1,
        universal_newlines=True,
        env=env,
        cwd=cwd,
    ) as p:
        for line in p.stdout:
            print(line, end="")

    if p.returncode != 0:
        raise subprocess.CalledProcessError(p.returncode, p.args)


def download_and_install_pip(python_exec):
    logging.info("Downloading and installing pip")
    pip_path = download_and_check("https://bootstrap.pypa.io/get-pip.py")
    run_cmd([str(python_exec), str(pip_path)])


def pip_install(python_exec, pip_package):
    logging.info(f"Installing {pip_package}")
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
            logging.info("Already downloaded")
            return filepath
        else:
            logging.info("Sha256 doesn't match downloading again.")

    with open(filepath, "w+b") as f:
        r = request.urlopen(url)
        for bits in r:
            f.write(bits)

    if sha and calc_hash(filepath) != sha:
        raise ValueError("Sha256 doesn't match")
    return filepath


def extract_files(filename, dest, skip_path=2):
    logging.info(f"Extracting {filename}")
    extracted_files = []
    with tarfile.open(filename) as tf:
        for ti in tf:
            dest_name = dest.joinpath("/".join(ti.name.split("/")[skip_path:]))
            logging.debug(dest_name)
            if ti.isdir():
                dest_name.mkdir(parents=True, exist_ok=True)
            tf._extract_member(ti, str(dest_name), not ti.isdir())
            extracted_files.append(dest_name)
    return extracted_files


def download_packages(
    packages: List[str], mac_version: str, ignore_packages: List[str]
):
    # Download packages and their dependencies if the depency is not in
    # ignore_packages. Return a list package files.
    downloads = packages[:]
    downloaded = []
    package_files = {}
    while downloads:
        package = downloads.pop(0)
        r = request.urlopen(f"https://formulae.brew.sh/api/formula/{package}.json")
        package_info = json.load(r)
        dependencies = package_info["dependencies"]
        bottle_url = package_info["bottle"]["stable"]["files"][mac_version]["url"]
        bottle_hash = package_info["bottle"]["stable"]["files"][mac_version]["sha256"]
        version = package_info["versions"]["stable"]
        logging.info(f"Downloading {package} (version: {version})")
        package_files[package] = {
            "file": download_and_check(bottle_url, bottle_hash),
            "version": version,
        }
        for dependency in dependencies:
            if (
                dependency not in ignore_packages
                and dependency not in packages
                and dependency not in downloaded
            ):
                downloads.append(dependency)
        downloaded.append(package)
    return package_files


def create_app_info(app_folder, app_name, version, icon):
    logging.info("Generating info.plist")
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


def create_launcher(app_folder, script_path, python_exec):
    logging.info("Creating lancher")
    exec_file = app_folder.joinpath("Contents/MacOS/run")
    c_temp_file = tempfile.mktemp(suffix=".c")
    logging.debug(f"\t{c_temp_file}")
    with open(c_temp_file, "w") as f:
        f.write(
            launcher_template.substitute(
                script_path=script_path,
                script_folder=relative_to(script_path.parent, exec_file.parent),
                script_name=script_path.name,
                python_exec=python_exec,
            )
        )
    logging.info("Compiling launcher")
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
    ignore_packages = dict_json.get("ignore_packages", [])
    pip_packages = dict_json.get("pip_packages", [])
    mac_version = dict_json["mac_version"]
    package_type = dict_json["app_package"]["source"]["type"]
    if package_type == "file":
        package_path = base_path.joinpath(dict_json["app_package"]["source"]["path"])
    else:
        package_url = dict_json["app_package"]["source"]["path"]
        sha = dict_json["app_package"]["source"].get("sha", None)
        package_path = download_and_check(package_url, sha)
    patches = dict_json["app_package"]["source"].get("patches", [])
    start_script = dict_json["app_package"]["start_script"]
    build_commands = dict_json["app_package"].get("build_commands", [])
    exclude_files = dict_json.get("cleanup", [])

    # Creating folders
    app_folder = base_path.joinpath(app_name + ".app")
    app_folder.mkdir(parents=True, exist_ok=True)

    resources_folder = app_folder.joinpath("Contents/Resources")
    resources_folder.mkdir(parents=True, exist_ok=True)

    binary_folder = app_folder.joinpath("Contents/MacOS")
    binary_folder.mkdir(parents=True, exist_ok=True)

    libs_folder = resources_folder.joinpath("libs")
    libs_folder.mkdir(parents=True, exist_ok=True)

    application_folder = resources_folder.joinpath("app")
    application_folder.mkdir(parents=True, exist_ok=True)

    start_script_path = application_folder.joinpath(start_script)
    start_script_folder = start_script_path.parent

    package_files = download_packages(packages, mac_version, ignore_packages)
    extracted_files = []
    for package in package_files:
        extracted_files.extend(
            extract_files(package_files[package]["file"], libs_folder)
        )

    if "python" in package_files:
        logging.info("Creating symlink")
        major, minor, _ = package_files["python"]["version"].split(".")
        site_packages = libs_folder.joinpath(f"lib/python{major}.{minor}/site-packages")
        link_site_packages = libs_folder.joinpath(
            f"Frameworks/Python.framework/Versions/{major}.{minor}/lib/python{major}.{minor}/site-packages"
        )
        os.symlink(
            relative_to(site_packages, link_site_packages.parent), link_site_packages
        )

    path_by_file = {}
    for extracted_file in extracted_files:
        #  path_by_file["/".join(extracted_file.parts[-2:])] = extracted_file
        try:
            path_by_file[str(extracted_file.parts[-1])].append(extracted_file)
        except:
            path_by_file[str(extracted_file.parts[-1])] = [extracted_file]

    #  print("writing json file")
    #  with open("/tmp/files.json", "w") as f:
    #  #  f.write(JSONEncoder().encode(path_by_file))
    #  json.dump(path_by_file, f)

    for package_file in extracted_files:
        extension = package_file.suffixes
        if package_file.is_file() and not package_file.is_symlink():
            try:
                # print(package_file)
                macho = MachO.MachO(str(package_file))
            except Exception:
                # Not lib or executable
                continue
            rewrote = False
            changer = SharedLibraryChanger(package_file, path_by_file, libs_folder)
            for header in macho.headers:
                if macho.rewriteLoadCommands(changer):
                    rewrote = True

            if rewrote:
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

    # Copying icon in the package
    shutil.copy2(base_path.joinpath(icon), resources_folder)

    # Creating Info.plist file
    create_app_info(app_folder, app_name, version, icon)

    # Copying or extracting app files inside the package
    if package_type == "file":
        shutil.copy2(package_path, str(application_folder))
    else:
        extract_files(package_path, start_script_folder, 1)

    # applying patch
    logging.info("Applying patches")
    for patch in patches:
        patch = base_path.joinpath(patch).resolve()
        logging.info(patch)
        run_cmd(["patch", "-p", "1", "-i", str(patch)], cwd=str(start_script_folder))

    c_libs_folders = [libs_folder.joinpath("lib").resolve()]
    c_include_folders = [libs_folder.joinpath("include").resolve()]
    my_env = os.environ.copy()
    my_env["PATH"] = str(PYTHON_EXEC.parent.resolve()) + ":" + my_env["PATH"]
    my_env["CFLAGS"] = (
        " ".join("-I{}".format(i) for i in c_include_folders)
        + " "
        + " ".join("-L{}".format(i) for i in c_libs_folders)
    )
    my_env["CXXFLAGS"] = (
        " ".join("-I{}".format(i) for i in c_include_folders)
        + " "
        + " ".join("-L{}".format(i) for i in c_libs_folders)
    )
    logging.info("Running scripts")
    logging.debug("PATH=" + my_env["PATH"])
    logging.debug("CFLAGS=" + my_env["CFLAGS"])
    logging.debug("CXXFLAGS=" + my_env["CXXFLAGS"])
    for build_command in build_commands:
        logging.info(build_command)
        build_command = shlex.split(build_command)
        run_cmd(build_command, env=my_env, cwd=str(start_script_folder))

    create_launcher(
        app_folder, start_script_path, relative_to(PYTHON_EXEC, start_script_folder)
    )

    # Excluding files marked to exclusion by user
    logging.info("Removing files")
    for exclude_file in exclude_files:
        if glob.has_magic(exclude_file):
            for ff in resources_folder.glob("**/{}".format(exclude_file)):
                logging.debug(f"\tremoving {ff}")
                if ff.is_dir():
                    shutil.rmtree(str(ff), ignore_errors=True)
                else:
                    ff.unlink()
        else:
            ff = resources_folder.joinpath(exclude_file)
            logging.debug(f"\tremoving {ff}")
            if ff.is_dir():
                shutil.rmtree(str(ff), ignore_errors=True)
            else:
                ff.unlink()


if __name__ == "__main__":
    main()
