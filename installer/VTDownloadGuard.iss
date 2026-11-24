#define MyAppName "VTDownloadGuard"
#define MyAppVersion "1.2.5"
#define MyAppPublisher "VTDownloadGuard"
#define MyAppExeName "VTDownloadGuard.exe"

[Setup]
AppId={{8D6B2A49-9B51-4F32-A4F7-9C35C18A7E11}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=..\dist
OutputBaseFilename=VTDownloadGuard-{#MyAppVersion}-win-x64-Setup
SetupIconFile=..\src\VTDownloadGuard\Assets\app.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "autostart"; Description: "Start automatically minimized to the system tray when Windows starts"; GroupDescription: "Startup options:"
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
Source: "..\dist\publish-standalone\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--open"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--open"; Tasks: desktopicon; IconFilename: "{app}\{#MyAppExeName}"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#MyAppName}"; ValueData: """{app}\{#MyAppExeName}"" --minimized"; Flags: uninsdeletevalue; Tasks: autostart

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: "--open"; Description: "Launch {#MyAppName} now"; Flags: nowait postinstall skipifsilent
Filename: "{app}\{#MyAppExeName}"; Parameters: "--open --after-update"; Flags: nowait; Check: ShouldLaunchOpenSilent
Filename: "{app}\{#MyAppExeName}"; Parameters: "--minimized --after-update"; Flags: nowait; Check: ShouldLaunchMinimizedSilent

[Code]
function ShouldLaunchOpenSilent(): Boolean;
begin
  Result := WizardSilent and (ExpandConstant('{param:OPENAFTERUPDATE|0}') = '1');
end;

function ShouldLaunchMinimizedSilent(): Boolean;
begin
  Result := WizardSilent and (ExpandConstant('{param:OPENAFTERUPDATE|0}') <> '1');
end;

procedure StopRunningApp();
var
  ResultCode: Integer;
begin
  Exec('taskkill.exe', '/IM VTDownloadGuard.exe /F /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(400);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopRunningApp();
  Result := '';
end;

function InitializeUninstall(): Boolean;
begin
  StopRunningApp();
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{userappdata}\VTDownloadGuard');
    if DirExists(DataDir) then
    begin
      if MsgBox('Do you also want to remove your VTDownloadGuard settings, scan history, and cache files?', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      begin
        DelTree(DataDir, True, True, True);
      end;
    end;
  end;
end;
