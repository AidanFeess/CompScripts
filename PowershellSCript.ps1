$users = Get-ADGroupMember -Identity 'Internals'
$pass = Read-Host -Prompt "password" -AsSecureString

foreach($user in $users){
    Set-ADAccountPassword -Identity $user -Reset -NewPassword $pass; 
    $temp = $user.SamAccountName;
    echo "$temp,Qu#BZyD?lemNxW-!" >> C:\Users\$env:Username\Desktop\export.csv
}
