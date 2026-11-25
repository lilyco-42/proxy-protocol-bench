#!/usr/bin/env python3
"""Install the pinned upstream Linux x86-64 benchmark engines into a directory."""
import argparse
import concurrent.futures
import hashlib
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile
import zipfile

# Release-asset SHA-256 digests. Cronet is the library commit used by sing-box 1.14.4.
ASSETS = {
    "sing-box": ("SagerNet/sing-box/v1.14.4/sing-box-1.14.4-linux-amd64.tar.gz",
                 "699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968"),
    "xray": ("XTLS/Xray-core/v26.11.9/Xray-linux-64.zip",
             "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82"),
    "mieru": ("enfein/mieru/v3.40.0/mieru_3.40.0_linux_amd64.tar.gz",
              "f08a4fd67eaa2819a30dda62ad6c2955dfd898563da133040f800b9ad3e2401f"),
    "mita": ("enfein/mieru/v3.40.0/mita_3.40.0_linux_amd64.tar.gz",
             "635dc431d5847cbd9567ed525ea55cc924949785617c6a5396bdd694917342a7"),
}
CRONET_URL = "https://raw.githubusercontent.com/SagerNet/cronet-go/c10c03c318db/lib/linux_amd64/libcronet.so"
CRONET_SHA256 = "23109c55b08829bb1a68682a61a64852b1bbf243753b153cbd8f6e4ea2c05294"


def install(target, binary):
    if binary == "libcronet.so":
        file, url, expected_hash = binary, CRONET_URL, CRONET_SHA256
    else:
        release, expected_hash = ASSETS[binary]
        org, project, tag, file = release.split("/")
        url = f"https://github.com/{org}/{project}/releases/download/{tag}/{file}"
    with tempfile.TemporaryDirectory(dir=target) as tmp:
        downloaded = Path(tmp) / file
        subprocess.run(["curl", "--fail", "--silent", "--show-error", "--location", "--retry", "2",
                        "--max-time", "600", "--output", str(downloaded), url], check=True)
        with downloaded.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != expected_hash:
                raise RuntimeError("SHA-256 mismatch for " + file)
        if file.endswith(".tar.gz"):
            with tarfile.open(downloaded, "r:gz") as archive:
                member = next(item for item in archive.getmembers() if item.isfile() and Path(item.name).name == binary)
                with archive.extractfile(member) as stream:
                    content = stream.read()
        elif file.endswith(".zip"):
            with zipfile.ZipFile(downloaded) as archive:
                content = archive.read(binary)
        else:
            content = downloaded.read_bytes()
        staged = Path(tmp) / binary
        staged.write_bytes(content)
        staged.chmod(0o700 if binary != "libcronet.so" else 0o600)
        staged.replace(target / binary)
        return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path)
    parser.add_argument("--role", choices=("client", "server", "both"), default="both")
    args = parser.parse_args()
    if (platform.system(), platform.machine()) != ("Linux", "x86_64"):
        parser.error("install equivalent versions manually on this platform")
    args.target.mkdir(parents=True, exist_ok=True, mode=0o700)
    binaries = ["sing-box", "xray"]
    if args.role in ("both", "server"):
        binaries.append("mita")
    if args.role in ("both", "client"):
        binaries.extend(("mieru", "libcronet.so"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        for binary in executor.map(lambda item: install(args.target, item), binaries):
            print("Installed", binary, flush=True)


if __name__ == "__main__":
    main()
