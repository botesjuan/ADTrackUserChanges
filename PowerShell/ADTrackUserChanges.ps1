<#
    Track User changes in AD,  save the security event logs to SQL table 

    4719
    4720 - user account was created
    4722 – A user account was enabled
    4725 – A user account was disabled
    4726 - account was deleted
    4728 – A member was added to a security global group
    4729 - member was removed from a security-enabled global group
    4732 – A member was added to a security local group
    4733 - member was removed from a security-enabled local group
    4737 - Security-enabled global group was changed
    4738 – A User account was changed
    
    4746 - A member was added to a security-disabled local group.
    4747 - a member was removed from a security-disabled local group
    4756 - A member was added to a security-enabled universal group
    4757 - Member was removed from a security-enabled universal group
    4758 - A security-enabled universal group was deleted
    4759 - security-disabled universal group was created
    4760 - security-disabled universal group was changed
    4761 - member was added to a security-disabled universal group
    4762 - member was removed from a security-disabled universal group
    4763 - security-disabled universal group was deleted

     https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor 

    Juan Botes
    20 February 2020
    InfoSec
#>
Import-Module ActiveDirectory
$scriptstarttime = (get-date)
Write-Output "#####"
Write-Output "AD Track User Changes script start time:  $scriptstarttime"
Write-Output "#####"

#   $HODomainControllers = "prd-hodc02.ho.fosltd.co.za","prd-hodc01.ho.fosltd.co.za","prd-hodc03.ho.fosltd.co.za","prd-hodc05.ho.fosltd.co.za","core-hodc06.ho.fosltd.co.za","core-hodc07.ho.fosltd.co.za"
$HODomainControllers = "prd-hodc02.ho.fosltd.co.za","prd-hodc01.ho.fosltd.co.za","prd-hodc03.ho.fosltd.co.za","prd-hodc05.ho.fosltd.co.za","prd-hodc08.ho.fosltd.co.za"
# $HODomainControllers = Get-ADDomainController -Filter  { isGlobalCatalog -eq $true} | Select-Object Hostname 
############################
Write-Output "Collecting Security Events from below list of Domain Controllers:" 
$HODomainControllers | FL

#   event id numbers  Monitored
#   https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor 
$LogName = "Security"

$eventIDRange1 = @(4720..4738)
$eventIDRange2 = @(4746..4764)    ###   filterhashtable  filter  by  range of sequential event IDs  ###   @(4624,4704,4705 + 4719..4740)  
Write-Output "Security Event ID Range 1: $($eventIDRange1.Count) "
Write-Output "Security Event ID Range 2: $($eventIDRange2.Count) "

#   Set Error Action to Silently Continue
$currentEAP = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"
#   Arrays to process results & output
$ADEventTrackingTable = @()

#   SQL  Database  Table
$dataSource = "PRD-sqls11.ho.fosltd.co.za\sqlsi1"    ###   "dev-sqls11.ho.fosltd.co.za\sqlsi1"
$database = "InfraUtil"
###  $ADUsers_TrackChanges_Staging = "[Audit].[ADUsers_TrackChanges_staging]"
$ADUsers_TrackChanges_Reporting = "[Audit].[ADUsers_TrackChanges_Reporting]"
$connectionString = "Server=$dataSource;Database=$database;trusted_connection=true;"

##############################################
#  READ  from  SQL   Last   Record   Inserted  Time  
##############################################

$GetLastDatedRecordInserted = "Select isnull(MAX([DateInserted]),GETDATE()) AS DateInserted
  FROM [InfraUtil].$ADUsers_TrackChanges_Reporting (Nolock) "

# read latest date record added into SQL Database table
Write-Output "SQL Instance $dataSource Database $database"

$LastDatedRecord = Invoke-Sqlcmd -ServerInstance $dataSource -Database $database -Query $GetLastDatedRecordInserted -QueryTimeout 15
Write-Output "Last Dated SQL Record Inserted:  $($LastDatedRecord.DateInserted) "
$TimeNow = (get-date)
$timesincelast = New-TimeSpan -Start $($LastDatedRecord.DateInserted) -End $TimeNow

#   MAX  read last   minutes or since last recorded added to database SQL
if ($timesincelast.TotalMinutes -ge 230) {
    $LastTime = (get-date).AddMinutes(-249) 
    }
    else { 
    $LastTime = $($LastDatedRecord.DateInserted).AddMinutes(-99)
}
  
####  $LastTime = $($LastDatedRecord.DateInserted).AddMinutes(-299)

Write-Output "Reading events Since:  $LastTime"

foreach($dc1hostname in $HODomainControllers) {    
    
    #$dc1 = $dc1hostname.Hostname
    $dc1 = $dc1hostname
    
    ##############################################
    #    collect  Event  from  security   log   track AD changes 
    ##############################################
     
    Write-Output "#  "
    $EventInfo1 = Get-WinEvent -FilterHashtable @{LogName=$LogName; ID = $eventIDRange1 ; Starttime=$LastTime } -ComputerName $dc1 | Select Message,TimeCreated,Id 
    $EventInfo2 = Get-WinEvent -FilterHashtable @{LogName=$LogName; ID = $eventIDRange2 ; Starttime=$LastTime } -ComputerName $dc1 | Select Message,TimeCreated,Id 
    
    $EventInfo = $EventInfo1 + $EventInfo2
    write-Output "Number Events collected:  $($eventinfo.count)    FROM DOMAIN CONTROLLER:  $dc1"
     
    ForEach($Result in $EventInfo) {        
       
        $SubjectAccountName=$TargetAccountName=$ChgAttGroupName=$PasswordLastSet=$UserPrincipalName = $null     # clear reset NULL
        $ChgAttValue3=$ChgAttValue4=$DoNotExpirePassword=$RECcomment = $null
        
        $ResultId = $Result.Id
        [string]$Item = $Result.Message        
        
        ######  SUBJECT  ACCOUNT
        $SubjectAccountName = $Item.SubString($Item.IndexOf("Subject:"))
        $SubjectAccountName = [regex]::Match($SubjectAccountName, 'Account Name:\s*(.*)\s*').Groups[1].Value
        $SubjectAccountName = $SubjectAccountName.Trim()
        
        #######    GROUP
        if ($Item.SubString($Item.IndexOf("Group:")) -ne "") {
            $ChangeAttributes = $Item.SubString($Item.IndexOf("Group:"))
            if ([regex]::Match($ChangeAttributes, 'Group Name:\s*(.*)\s*').Groups[1].Value -ne "") {
                $ChgAttGroupName = [regex]::Match($ChangeAttributes, 'Group Name:\s*(.*)\s*').Groups[1].Value
            }
            if ([regex]::Match($ChangeAttributes, 'Account Name:\s*(.*)\s*').Groups[1].Value -ne "") {
                $ChgAttGroupName = [regex]::Match($ChangeAttributes, 'Account Name:\s*(.*)\s*').Groups[1].Value
            }
            $ChgAttGroupName = $ChgAttGroupName.Trim()
        }
        
        #######    Member

        if ($Item.SubString($Item.IndexOf("Member:")) -ne "") {
            $TempMember = $Item.SubString($Item.IndexOf("Member:"))            
            $TargetAccN = [regex]::Match($TempMember, 'Account Name:\s*(.*)\s*').Groups[1].Value  
            $TargetAccN = $TargetAccN.Trim()
            $TargetAccountName = Get-ADUser -Identity $TargetAccN | Select-Object -ExpandProperty SamAccountName            
            $TargetAccountName = $TargetAccountName.Trim()
        }
        
        #######  TARGET  ACCOUNT              

        if ($Item.SubString($Item.IndexOf("Target Account:")) -ne "") {
            $TargetAccountName = $Item.SubString($Item.IndexOf("Target Account:"))
            $TargetAccountName = [regex]::Match($TargetAccountName, 'Account Name:\s*(.*)\s*').Groups[1].Value
            $TargetAccountName = $TargetAccountName.Trim()
        }

        ###  TARGET  ACCOUNT   = '-'  convert   SID  to Domain object name
        if ($TargetAccountName -eq "-") {
            $Memberstr = $Item.SubString($Item.IndexOf("Member:"))
            $SecurityID = [regex]::Match($Memberstr, 'Security ID:\s*(.*)\s*').Groups[1].Value
            $SecurityID = $SecurityID.Trim()
            ###    SID convert -  find Domain object name
            $objSID = New-Object System.Security.Principal.SecurityIdentifier("$SecurityID")
            $objUser = $objSID.Translate( [System.Security.Principal.NTAccount]) 
            $TargetAccountName = $objUser.Value
        }       

        #######  UPN   User Principal Name   other  attributes
        
        if  ($Item.SubString($Item.IndexOf("Attributes:")) -ne "") {
            $Attributesupn = $Item.SubString($Item.IndexOf("Attributes:"))
            $UserPrincipalName = [regex]::Match($Attributesupn, 'User Principal Name:\s*(.*)\s*').Groups[1].Value
            $UserPrincipalName = $UserPrincipalName.Trim()            

            $ChgAttValue4 = [regex]::Match($Attributesupn, 'Account Expires:\s*(.*)\s*').Groups[1].Value
            $ChgAttValue4 = $ChgAttValue4.Replace("'","")
            $ChgAttValue4 = $ChgAttValue4.Trim() 

            $PasswordLastSet = [regex]::Match($Attributesupn, 'Password Last Set:\s*(.*)\s*').Groups[1].Value
            $PasswordLastSet = $PasswordLastSet.Trim()
        }       

        #######    Comment  Message  summary

        $TempStr3 = $Item.Split([Environment]::NewLine) | Select -First 1
        $TempStr3 = $TempStr3.Replace("'","")                              ####     remove commas in text
        $RECcomment = $TempStr3.Trim()             
        
        if ($ResultId -eq 4722) {                 ########################    account was enabled                
                $ChgAttValue3 = "Account Enabled True"                
        }  
        if ($ResultId -eq 4725) {                 #######################    account was enabled                
                $ChgAttValue3 = "Account Disabled"                
        }  
        if ($ResultId -eq 4738) {        ################################    Password Not Required Enabled                                                
                
                if ($Item.SubString($Item.IndexOf("Don't Expire Password'")) -ne "") {                   
                    $RECcomment = "Password Not Required Enabled"
                     
                    $DoNotExpirePassword = "True"
                    $TargetAccountName = $Item.SubString($Item.IndexOf("Target Account:"))
                    $TargetAccountName = [regex]::Match($TargetAccountName, 'Account Name:\s*(.*)\s*').Groups[1].Value
                    $TargetAccountName = $TargetAccountName.Trim()                    
                }
                 if ($Item.SubString($Item.IndexOf("Account Enabled")) -ne "") {                   
                    $RECcomment = "User Account was Enabled"
                     
                    $ChgAttValue3 = "Account Enabled True"
                    $TargetAccountName = $Item.SubString($Item.IndexOf("Target Account:"))
                    $TargetAccountName = [regex]::Match($TargetAccountName, 'Account Name:\s*(.*)\s*').Groups[1].Value
                    $TargetAccountName = $TargetAccountName.Trim()                    
                }
        }                              
        ###   Get  Sam  Account Name from AD Object  distinguishedName     
        if ($TargetAccountName -like 'CN=*') {
           $SamAccountName = Get-ADObject -Server "prd-hodc02.ho.fosltd.co.za:3268" -Filter {distinguishedName -eq $TargetAccountName} -property SamAccountName | Select-Object SamAccountName 
           $TargetAccountName = $SamAccountName.SamAccountName
        }        

        ###########################################
        # remove comma s from event message
        # 
        $TempStr2 = $Result.Message
        $TempStr2 = $TempStr2.Replace("'","")

        $ChgAttGroupName = $ChgAttGroupName.Replace("'"," ")

        <# ### DEBUG          check account enabled found
        if (($ChgAttValue3 -eq "Account Enabled True" ) -or ($DoNotExpirePassword -eq "True")) { 
            write-output "######################"
            write-output "                Result Event Id:  $ResultId "
            write-output "Account Enable VAR ChgAttValue3: $ChgAttValue3"
            write-output "         Do Not Expire Password: $DoNotExpirePassword"
            Write-Output "                           Time: $($Result.TimeCreated) "
            Write-Output " TARGET account/who was modifed: $TargetAccountName "
            Write-Output "     Who was doing change in AD:  $SubjectAccountName "
        }
        #>
        #  insert variables  into hash table        
        $hItemDetails = New-Object -TypeName psobject -Property @{
                DateOccured = $Result.TimeCreated
                EventID = $ResultId            
                EventMessage = "Event ID $ResultId $TempStr2"
                DomainController = $dc1
                SubjectAccountName = $SubjectAccountName
                TargetAccountName = $TargetAccountName
                ChgAttGroupName = $ChgAttGroupName
                DoNotExpirePassword = $DoNotExpirePassword
                PasswordLastSet = $PasswordLastSet
                UserPrincipalName = $UserPrincipalName
                ChgAttValue3 = $ChgAttValue3
                ChgAttValue4 = $ChgAttValue4
                EventComment = $RECcomment
        }
        ###    Add each item  hash  table to array
        $ADEventTrackingTable += $hItemDetails 
    }   ###    ForEach  Event $Result 
    
    ###   insert all collected events into SQL table 

    foreach($Evt in $ADEventTrackingTable) {
        $DateOccured        = $Evt.DateOccured
        $EventID            = $Evt.EventID
        $EventMessage       = $Evt.EventMessage
        $DomainController   = $Evt.DomainController
        $SubjectAccountName = $Evt.SubjectAccountName
        $TargetAccountName  = $Evt.TargetAccountName
        $ChgAttGroupName    = $Evt.ChgAttGroupName
        $DoNotExpirePassw   = $Evt.DoNotExpirePassword
        $PasswordLastSet    = $Evt.PasswordLastSet
        $UPN  = $Evt.UserPrincipalName
        $ChgAttVal3       = $Evt.ChgAttValue3
        $ChgAttVal4       = $Evt.ChgAttValue4
        $EventComment       = $Evt.EventComment        
        
        $SQL_InsertRecord = $null
        $SQL_InsertRecord = "INSERT INTO [InfraUtil].$ADUsers_TrackChanges_Reporting
            (  [EventID],[DateOccured],[DomainController],[SubjectAccountName]
              ,[TargetAccountName],[ChgAttGroupName],[DoNotExpirePassword],[PasswordLastSet]
              ,[UserPrincipalName],[ChgAttValue3],[ChgAttValue4],[EventComment]
              ,[EventMessage] )

            VALUES ('$EventID','$DateOccured','$DomainController','$SubjectAccountName',
                    '$TargetAccountName','$ChgAttGroupName','$DoNotExpirePassw','$PasswordLastSet',
                    '$UPN','$ChgAttVal3','$ChgAttVal4','$EventComment','$EventMessage' );"

            # Invoke-Sqlcmd -ServerInstance $dataSource -Database $database -Query $SQL_InsertRecord
            
            try {
                Invoke-Sqlcmd -Query $SQL_InsertRecord -ServerInstance $dataSource -database $database  -QueryTimeout 65535 -ErrorAction 'Stop'                 
            } catch {
                Write-Output "***   ERROR when running sql   ***"
                $SQL_InsertRecord                
            }            
    }   ###   for each event collected inserted  into  SQL table    
    
    Write-Output "Total events:  $($ADEventTrackingTable.Count)"
    $ADEventTrackingTable = @()   
}    ###    for each  DC in list

###  collect all accounts created and recording exchange audit log
###  then close exchange 2010 remote PS session
###  collect once in the morning before 7am
$scriptENDtime = (get-date)
$ListExchangeServers = "http://prd-exch01.ho.fosltd.co.za/PowerShell" #,"http://prd-exch02.ho.fosltd.co.za/PowerShell","http://prd-exch03.ho.fosltd.co.za/PowerShell","http://prd-exch04.ho.fosltd.co.za/PowerShell","http://prd-exch05.ho.fosltd.co.za/PowerShell"
$5days = ((Get-Date).AddDays(-5))            
$TimeEnd = get-date

if (($scriptENDtime.Minute -ge 1 ) -and ($scriptENDtime.Minute -le 59 ) -and ($scriptENDtime.Hour -eq 11 )) { 
    Write-Output "Collecting Eachange Audit Security Logs from :" 
    $ListExchangeServers | FL    

    foreach($MBXSRV in $ListExchangeServers) {
    
        ###  Connect ot exchange audit logs to extract new mailbox create by Admins        
        $ConnectionUri = $MBXSRV
        $ConnectionUri
        $exchsession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionUri -Authentication Kerberos
        Import-PSSession $exchsession
        
        $NewExchMbxAccounts = Search-AdminAuditLog -StartDate $5days -EndDate $TimeEnd -Cmdlets New-Mailbox | select RunDate,Caller,ObjectModified,Succeeded
        $NewExchMbxAccounts | FT -AutoSize

        foreach($newmbx in $NewExchMbxAccounts) {
            $ObjectModified = $newmbx.ObjectModified
            $endObjectModified = $ObjectModified.Substring($ObjectModified.LastIndexOf('/')+1)
            # $endObjectModified
            $SAMidObjectModified = Get-ADUser -Filter { (name -Like $endObjectModified) -or (displayName -Like $endObjectModified) } | select SamAccountName
            $SAMidObjectModifiedValue = $SAMidObjectModified.SamAccountName
        
            $EventID = "7777"
            $DateOccured = $newmbx.RunDate
            $DomainController = $MBXSRV 
            
            $caller = $newmbx.Caller
            $endname = $caller.Substring($caller.LastIndexOf('/')+1)
            $TargetAccountName = $SAMidObjectModifiedValue
            $SubjectAccountNameValue = Get-ADUser -Filter { (name -Like $endname) } | select SamAccountName
            $SubjectAccountName = $SubjectAccountNameValue.SamAccountName

            $ChgAttGroupName = $DoNotExpirePassw = $PasswordLastSet = ""
            $UPN = $ChgAttVal3 = $ChgAttVal4 = ""
            $EventComment = $EventMessage = "Exchange Audit Log Entry"
        

            $SQL_InsertRecord = $null
            $SQL_InsertRecord = "INSERT INTO [InfraUtil].$ADUsers_TrackChanges_Reporting
                (  [EventID],[DateOccured],[DomainController],[SubjectAccountName]
                  ,[TargetAccountName],[ChgAttGroupName],[DoNotExpirePassword],[PasswordLastSet]
                  ,[UserPrincipalName],[ChgAttValue3],[ChgAttValue4],[EventComment]
                  ,[EventMessage] )

                VALUES ('$EventID','$DateOccured','$DomainController','$SubjectAccountName',
                        '$TargetAccountName','$ChgAttGroupName','$DoNotExpirePassw','$PasswordLastSet',
                        '$UPN','$ChgAttVal3','$ChgAttVal4','$EventComment','$EventMessage' );"
                            
                try {
                    Invoke-Sqlcmd -Query $SQL_InsertRecord -ServerInstance $dataSource -database $database  -QueryTimeout 1000 -ErrorAction 'Stop'                 
                } catch {
                    Write-Output "***   ERROR when running sql   ***"
                    $SQL_InsertRecord                
                }
            $SQL_InsertRecord
        }
        Remove-pssession $exchsession
    }
}



#####################################################
#  EMAIL   report   count
   
if (($scriptENDtime.Day -eq 21 ) -and ($scriptENDtime.Hour -eq 16 )) { 
   
    Write-Output "Email report on day $($scriptENDtime.Day) of each Month."

    $QueryLastRecordInserted = "Select isnull(MAX([DateInserted]),GETDATE()) AS DateInserted FROM [InfraUtil].[Audit].[ADUsers_TrackChanges_Reporting] (Nolock)"
    $QueryTotalNumberRecords = "SELECT COUNT(*) FROM [InfraUtil].[Audit].[ADUsers_TrackChanges_Reporting] WITH (NOLOCK)"

    $LastRecordInserted = Invoke-Sqlcmd -ServerInstance $dataSource -Database $database -Query $QueryLastRecordInserted
    $TotalRecords = Invoke-Sqlcmd -ServerInstance $dataSource -Database $database -Query $QueryTotalNumberRecords
    
    $CurrentDate = $(get-date).ToString("ddMMyyyy")
    $AttachFile = "D:\SupportStore\Scripts\ADTrackUserChanges\ScriptResults.txt"
    
    ###############################################
    #   Send Mail message    email   
    $textEncoding = [System.Text.Encoding]::UTF8 
    $reportSubject = "Health Check Self Service Portal and Track AD Changes Reports" 
    
    $body2 = "<HTML><HEAD><META http-equiv=""Content-Type"" content=""text/html; charset=iso-8859-1"" /><TITLE></TITLE></HEAD>"
    $body2 += "<BODY bgcolor=""#FFFFFF"" style=""font-size: Small; font-family: TAHOMA; ""><P>"
    $body2 += "Health Check of Track AD Changes + SQL Table  Check  email  <br>"    
    $body2 += "   <br>"
    $body2 += "data Source $dataSource  <br>"
    $body2 += "PROD database $database  <br>"
    $body2 += "   <br>"
    $body2 += "PROD SQL Table Query:    <br>"
    $body2 += " $QueryLastRecordInserted  <br>"
    $body2 += "   <br>"
    $body2 += "Task Schedule Server PRD-WSSMAN01  <br>"
    $body2 += "Last SQL Record Inserted into AD Tracking Table: $($LastRecordInserted.DateInserted) <br>"
    $body2 += "   <br>"
    $body2 += "script schedule path: \\prd-wssman01\d$\SupportStore\Scripts\ADTrackUserChanges <br>"
    $body2 += "   <br>"
    $body2 += "Total Records in AD Tracking Table: $($TotalRecords.Column1) <br>"
    $body2 += "<a href=http://infraweb.ho.fosltd.co.za/SelfService/#/ActiveDirectory/Track/TrackChanges target=""_blank"">Front END: Self Service Portal</a><br>"
    
    $smtpServer = "smtp.tfg.co.za"
    $fromEMail = "TrackADChanges@tfg.co.za"
    $testRecipient = "juanb@tfg.co.za"
    $EMAILreportTO = "juanb@tfg.co.za","jeansn@tfg.co.za","HeinrichF@tfg.co.za"  ###  "DLTFGInfotecInfrastructureSQLDBA@tfg.co.za"  ### "windowsserversystems2@tfg.co.za"
           
    Send-Mailmessage -smtpServer $smtpServer -from $fromEMail -to $EMAILreportTO -subject $reportSubject -body $body2 -BodyAsHtml -Encoding $textEncoding
} 
else {
    Write-Output "NOT Emailing a Report." 
}
##############################################
$scriptENDtime = (get-date)
Write-Output " "
Write-Output "###############################################################"
Write-Output "AD Track User Changes script Ended:  $scriptENDtime"
Write-Output "###############################################################"
