Windows core bundle (generated, do not edit)
=============================================

xray.exe        Xray 26.3.27  (XTLS/Xray-core, Xray-windows-64.zip)
geoip.dat       from the same Xray archive
geosite.dat     from the same Xray archive
sing-box.exe    sing-box 1.14.4 (SagerNet/sing-box, sing-box-1.14.4-windows-amd64.zip)

version.txt          Xray version stamped for the in-app core version check
singbox-version.txt  sing-box version for diagnostics

.github/workflows/build-windows.yml downloads these exact releases on every
build. To refresh locally, download the two Windows amd64 archives, copy the
files above into this folder, and write the version strings to the two txt
files.
