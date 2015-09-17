mkdir package\lib
mkdir package\lib
mkdir package\lib\net40

copy "..\SoftFluent.SocialEmailLogin\bin\Release\SoftFluent.SocialEmailLogin.dll" "package\lib\net40"
copy "..\SoftFluent.SocialEmailLogin\bin\Release\SoftFluent.SocialEmailLogin.pdb" "package\lib\net40"
copy "SoftFluent.SocialEmailLogin.csproj.nuspec" "package\"
nuget pack "package\SoftFluent.SocialEmailLogin.csproj.nuspec"
rmdir /S /Q package