[Version]
Class=IEXPRESS
SEDVersion=3

[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=1
HideExtractAnimation=0
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=%InstallPrompt%
DisplayLicense=%DisplayLicense%
FinishMessage=%FinishMessage%
TargetName=%TargetName%
FriendlyName=%FriendlyName%
AppLaunched=%AppLaunched%
PostInstallCmd=%PostInstallCmd%
AdminQuietInstCmd=%AdminQuietInstCmd%
UserQuietInstCmd=%UserQuietInstCmd%
SourceFiles=SourceFiles

[Strings]
InstallPrompt=
DisplayLicense=
FinishMessage=VANT OpenSearch Agent instalado correctamente.
TargetName=C:\Users\leonardo.varona\3D Objects\develop\VANT-SIEM\dist\opensearch-agent-installer\setup.exe
FriendlyName=VANT OpenSearch Agent Setup
AppLaunched=setup.cmd
PostInstallCmd=<None>
AdminQuietInstCmd=setup.cmd
UserQuietInstCmd=setup.cmd
FILE0="setup.cmd"
FILE1="package.zip"

[SourceFiles]
SourceFiles0=C:\Users\leonardo.varona\3D Objects\develop\VANT-SIEM\opensearch\agent\installer\windows_setup\

[SourceFiles0]
%FILE0%=
%FILE1%=
