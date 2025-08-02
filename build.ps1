
param (
	[switch]$TestIda = $False,
	[switch]$Release = $False
)

$VS_SOLUTION_DIR = ".\build\vs2022"
$ARTIFACTS_PATH = if ($Release) { "$VS_SOLUTION_DIR\artifacts-release" } else { "$VS_SOLUTION_DIR\artifacts-debug" }

$VS_PATH="C:\Program Files\Microsoft Visual Studio\2022\Community"
$DEVENV_PATH="$VS_PATH\Common7\IDE\devenv.com"
$MSBUILD_PATH="$VS_PATH\MSBuild\Current\Bin\MSBuild.exe"
$CMAKE_PATH="$VS_PATH\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"

# IDA Paths
$IDA_SDK="E:\dev\idasdk91"
$IDA_BIN="E:\dev\IDA Professional 9.1"
$IDA_TEST_SAMPLE = "$ARTIFACTS_PATH\ida-sample.exe"

# Generate VS2022 Solution
#if (!(Test-Path -Path $VS_SOLUTION_DIR)) {
  &"$CMAKE_PATH" --preset=vs2022 `
      -DMOMO_ENABLE_RUST_CODE=0 `
      -DMOMO_ENABLE_IDA_SYNC=1 `
      -DIDASDK="$IDA_SDK" `
	  -DIDABIN="$IDA_BIN"
  if(!$?) { Exit $LASTEXITCODE }
#}

# Build Solution
# &"$DEVENV_PATH" $VS_SOLUTION_DIR\emulator.sln /Build
&"$MSBUILD_PATH" $VS_SOLUTION_DIR\emulator.sln
if(!$?) { Exit $LASTEXITCODE }

if ($TestIda) {
	Write-Host "\nStarting IDA test..." -ForegroundColor Yellow
	
	# If there isn't already a compilation database
#	 if (!(Test-Path -Path "$IDA_TEST_SAMPLE.i64")) {
#		Write-Host "`nGenerating IDA database..." -ForegroundColor Yellow
		
		# Use IDA Pro text mode UI to use less system resources.
#		&"$IDA_BIN\idat.exe" -A $IDA_TEST_SAMPLE
#		if(!$?) { Exit $LASTEXITCODE }
#	}

	# Start the analysis debugger
	# &"$ARTIFACTS_PATH\analyzer.exe" -d -z $IDA_TEST_SAMPLE
	Start-Process -FilePath "$ARTIFACTS_PATH\analyzer.exe" `
		-ArgumentList "-d","-z","$IDA_TEST_SAMPLE"
		# -WorkingDirectory "$ARTIFACTS_PATH" `

	Start-Sleep -Seconds 3

	# Start the IDA instance
	# &"$MSBUILD_PATH" $VS_SOLUTION_DIR\src\ida-plugin\ida-sogen-sync.sln /p:Configuration=Debug # -t:Debug
	Start-Process -FilePath "$IDA_BIN\ida.exe" -ArgumentList `
		"-z10000","-rgdb@127.0.0.1:28960","$IDA_TEST_SAMPLE.i64"
}
