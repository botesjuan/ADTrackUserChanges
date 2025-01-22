D:
CD D:\SupportStore\Scripts\ADTrackUserChanges

copy D:\SupportStore\Scripts\ADTrackUserChanges\ScriptResults.txt D:\SupportStore\Scripts\ADTrackUserChanges\ScriptResults_previous.txt /Y

Powershell.exe -command "&{D:\SupportStore\Scripts\ADTrackUserChanges\ADTrackUserChanges.ps1}" >D:\SupportStore\Scripts\ADTrackUserChanges\ScriptResults.txt




