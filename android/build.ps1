# Builds custodly-portal.apk straight with the Android SDK tools (no Gradle: the installed JDK is newer
# than Gradle's Android plugin supports). Usage: powershell -File build.ps1 [-Version 0.4.0 -Code 4]
param([string]$Version = "0.4.0", [int]$Code = 4)
$ErrorActionPreference = "Stop"
$d = $PSScriptRoot; Set-Location $d
$sdk = "$env:LOCALAPPDATA\Android\Sdk"; $bt = "$sdk\build-tools\36.0.0"; $jar = "$sdk\platforms\android-35\android.jar"
Remove-Item -Recurse -Force build, custodly-portal.apk -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force build\classes, build\dex | Out-Null
& "$bt\aapt2.exe" compile --dir res -o build\res.zip
& "$bt\aapt2.exe" link -o build\base.apk -I $jar --manifest AndroidManifest.xml --min-sdk-version 33 --target-sdk-version 35 --version-code $Code --version-name $Version build\res.zip
$src = Get-ChildItem src -Recurse -Filter *.java | ForEach-Object FullName
javac -encoding UTF-8 --release 11 -Xlint:-options -cp $jar -d build\classes @src
if ($LASTEXITCODE) { throw "javac failed" }
$cls = Get-ChildItem build\classes -Recurse -Filter *.class | ForEach-Object FullName
& "$bt\d8.bat" --lib $jar --min-api 33 --output build\dex @cls
Push-Location build\dex; jar --update --file ..\base.apk classes.dex; Pop-Location
& "$bt\zipalign.exe" -f 4 build\base.apk build\aligned.apk
if (-not (Test-Path debug.keystore)) { keytool -genkeypair -keystore debug.keystore -storepass android -keypass android -alias custodly -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Custodly Phone" }
& "$bt\apksigner.bat" sign --ks debug.keystore --ks-pass pass:android --key-pass pass:android --out custodly-portal.apk build\aligned.apk
& "$bt\apksigner.bat" verify custodly-portal.apk
Get-Item custodly-portal.apk | Select-Object Name, Length