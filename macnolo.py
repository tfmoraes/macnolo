import hashlib
import json
import pathlib
import shutil
import sys
import tarfile
from urllib import request

CACHE_FOLDER = pathlib.Path(".cache")
CACHE_FOLDER.mkdir(parents=True, exist_ok=True)


def calc_hash(filename):
    with open(filename, "r+b") as f:
        h = hashlib.sha256(f.read())
        return h.hexdigest()


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
    with tarfile.open(filename) as tf:
        for ti in tf:
            print(ti.name)
            dest_name = str(dest.joinpath('/'.join(ti.name.split("/")[2:])))
            if ti.isdir():
                dest_name.mkdir(parents=True, exist_ok=True)
            tf._extract_member(ti, dest_name)


def main():
    json_fname = sys.argv[1]
    with open(json_fname) as json_input:
        dict_json = json.load(json_input)

    app_name = dict_json["app_name"]
    version = dict_json["version"]
    packages = dict_json["packages"]
    ignore_packages = dict_json["ignore_packages"]
    mac_version = dict_json["mac_version"]
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

    app_folder = pathlib.Path(app_name)
    libs_folder = app_folder.joinpath("libs")
    libs_folder.mkdir(parents=True, exist_ok=True)

    for package in package_files:
        extract_files(package, libs_folder)


if __name__ == "__main__":
    main()
