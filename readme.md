# Macnolo

**Macnolo** is a tool to create Mac Application package (.app file) from python scripts including all its dependencies. Macnolo gets all dependencies from **brew**, **pip**. The package definition are written in a json file.

## JSON File

    {
        "app_name": "Application name",
        "version": "Application version",
        "identifier": "Application identifier, generaly the application site backward, like com.github.macnolo",
        "icon": "icns icon file path",
        "packages": [list of brew packages],
        "ignore_packages": [list of brew packages to ignored],
        "mac_version": "version of macos",
        "pip_packages": [list of pip packages],
        "commands": [
            list of shell commands. the commands are run inside the application resource folder.
        ],
        "app_package": {
            "source":{
                "type": "url or file",
                "path": "https or file path",
                "sha": "sha256 of file (not necessary)",
                "patches": [list of patch files]
            },
            "start_script": "start script path",
            "build_commands": [
                build command to be run inside the application, like build some C or Cython modules.
            ]
        },
        "cleanup": [
            "list of files, directories or glob patterns to be removed"
        ]
    }

## Usage

In terminal run:

    $ python3 macnolo package_path.json

It'll generate the .app file inside the package_path.json folder.
