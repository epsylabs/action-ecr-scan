import json
import os
import shutil
import zipfile
from urllib.request import urlopen, urlretrieve

url = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"

kernel_cves = []

print("Fetching base data")
response = urlopen(url)
json_data = json.loads(response.read())
full_list_url = ""
for asset in json_data.get("assets", []):
    if "_all_" in asset.get("name"):
        full_list_url = asset.get("browser_download_url")

print("Downloading database (it takes some time)")
filehandle, _ = urlretrieve(full_list_url)

print("Extracting files")
with zipfile.ZipFile(filehandle) as f:
    f.extractall()

    with zipfile.ZipFile("cves.zip") as g:
        g.extractall()
        print("Inspecting database")
        for subdir, dirs, files in os.walk("cves"):
            for file in files:
                path = os.path.join(subdir, file)
                cve = json.load(
                    open(path),
                )
                if type(cve) is not dict:
                    continue
                descriptions = (
                    cve.get("containers", {}).get("cna", {}).get("descriptions", [])
                )
                if descriptions and "kernel" in list(
                    filter(
                        lambda desc: desc.get("lang").lower().startswith("en"),
                        descriptions,
                    )
                )[0].get("value"):
                    cve_id = cve.get("cveMetadata", {}).get("cveId")
                    kernel_cves.append(cve_id)

print("Updating kernel.txt")
with open(r"kernel.txt", "w") as fp:
    for kernel_cve in kernel_cves:
        fp.write("%s\n" % kernel_cve)

print("Cleaning up unnecessary files")
shutil.rmtree("cves")
os.remove("cves.zip")
