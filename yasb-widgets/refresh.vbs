' Silent HTTP GET helper invoked by YASB widgets to trigger a dashboard
' refresh without flashing a console window. wscript.exe is GUI-subsystem,
' so unlike curl.exe it never allocates a console.
'
' Usage: wscript.exe refresh.vbs <url>
On Error Resume Next
If WScript.Arguments.Count < 1 Then WScript.Quit
Dim http : Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", WScript.Arguments(0), False
http.Send
