### emir_m@tvsi.ru ###
### Скрипт отсылает события журналов Kaspersky в чат Телеграм ###
### This script sends Kaspersky event logs into a Telegram chat ###

### function removes special characters from text (otherwise telegram will return 403 error)
function Set-EscapeCharacters {
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [String]
        $string
    )
    $string = $string.replace('_', '')
    $string = $string.replace('*', '')
    $string = $string.replace('~', '')
    $string = $string.replace('>', '')
    $string = $string.replace('<', '')
    $string = $string.replace('#', '')
    $string = $string.replace('+', '')
    $string
}

### current working dir
$current_path = $PSScriptRoot

Import-Module -Name "PoshGram"
[string]$botToken="342342341234:SDGFGDFHds-oVDHYUsbdBFAZDFBFDZFV-w1" # bot token here
[string]$chatId="-523645345634" # chat ID here

### get the date of previous query launch ###
$prev_date = Get-Content -Path "$($current_path)\last_event_date.txt"

### form the new sql query file with a new datetime (query selects all events that happened since last script run) ###
$sql_query = @"
SELECT e.nId, e.tmRiseTime, e.strEventType,	e.wstrEventTypeDisplayName, e.wstrDescription, e.wstrGroupName, h.wstrDisplayName,
CAST(((h.nIp / 16777216) & 255) AS varchar(4)) + '.' +
CAST(((h.nIp / 65536) & 255) AS varchar(4)) + '.' +
CAST(((h.nIp / 256) & 255) AS varchar(4)) + '.' +
CAST(((h.nIp) & 255) AS varchar(4)) as strIp
FROM v_akpub_ev_event e
INNER JOIN v_akpub_host h ON h.nId=e.nHostId
WHERE e.tmRiseTime>'$($prev_date)'
AND e.strEventType IN ('GNRL_EV_VIRUS_FOUND', 'GNRL_EV_ATTACK_DETECTED', 'GNRL_EV_OBJECT_CURED', 'GNRL_EV_OBJECT_DELETED', 'GNRL_EV_OBJECT_QUARANTINED', 'GNRL_EV_OBJECT_NOTCURED', 'GNRL_EV_SUSPICIOUS_OBJECT_FOUND', 'GNRL_EV_VIRUS_OUTBREAK', 'GNRL_EV_APPLICATION_LAUNCH_DENIED', 'GNRL_EV_PTOTECTION_LEVEL_CHANGED')
ORDER BY e.tmRiseTime ASC
"@

### save newly formed sql file ###
Out-File -Force -InputObject $sql_query -Path "$($current_path)\query.sql"
sleep 1

### execute db query using new sql file ###
### (klsql.exe is a tool that queries Kaspersky logs, if the query is not NULL, it will output results to the current directory as an xml file) ###
### (otherwise klsql.exe returns nothing) ###
& "$($current_path)\klsql2.exe" -i query.sql -o result_events.xml

### wait for xml file to be formed (usually it takes around 3 seconds) ###
sleep 5
if (!(Test-Path -Path "$($current_path)\result_events.xml" -PathType Leaf)) { sleep 10 }

### parse xml file ###
[xml]$xmlContent = [xml](Get-Content -Path "$($current_path)\result_events.xml")

### if not empty (if there were no events, klsql.exe returns nothing, so an extra check is needed) ###
if ($xmlContent -ne $null) 
{
    ### retrieve event properties into an array of hashtables ###
    $eventlist_ht = @()

    foreach($record in $xmlContent.data.record)
    {
        $event_hashtable = @{}
        $event_hashtable.Add('event_type', ($record.field | ?{$_.name -eq "strEventType"}).value)
        $event_hashtable.Add('event_name', ($record.field | ?{$_.name -eq "wstrEventTypeDisplayName"}).value)
        $event_hashtable.Add('event_date', ($record.field | ?{$_.name -eq "tmRiseTime"}).value)
        $event_hashtable.Add('event_ip', ($record.field | ?{$_.name -eq "strIp"}).value)
        $event_hashtable.Add('event_usergroup', ($record.field | ?{$_.name -eq "wstrGroupName"}).value)
        $event_hashtable.Add('event_hostname', ($record.field | ?{$_.name -eq "wstrDisplayName"}).value)
        $event_hashtable.Add('event_details', ($record.field | ?{$_.name -eq "wstrDescription"}).value)

        $eventlist_ht += , $event_hashtable
    }

    $eventlist_sorted = @()

    ### get only unique events sorted by event_type, event_ip ###
    ### if there is only one event, do not sort ###
    if ($eventlist_ht.Count -eq 1)
    {
        $eventlist_sorted += $eventlist_ht
    }
    else
    {   ### this also cuts duplicate (similar) events, only return unique ###
        $eventlist_sorted = $eventlist_ht | Sort-Object -Property event_type, event_ip -Unique
        $eventlist_sorted = $eventlist_sorted | Sort-Object -Property event_date
    }

    ### fix weird behavior when PowerShell transforms array into an element when array.Count is 1 ###
    if ($eventlist_sorted -is [Hashtable])
    {
        $eventlist_sorted = @(,$eventlist_sorted)
    }

    ### form the messages and push notifications to telegram ###
    foreach($event in $eventlist_sorted)
    {
        if ($event['event_details'] -ne "<NULL>") 
        {
            $text = $event['event_details'].Split('Дата выпуска баз')[0]
            $text = $text.Split('SHA')[0]
            $text = $text.Split('Хеш')[0]
            $text = Set-EscapeCharacters $text
        }
        else { $text = "No description" }

        $rf = [DateTime]$event['event_date']
        $ev_date = $rf.ToString("HH:mm:ss dd/MM/yyyy")
        $messagetext = "<b>[$($event['event_type'])]</b>
<pre>$($event['event_name'])</pre>
<b>Время события:</b> <pre>$($ev_date)</pre>
<b>IP-адрес:</b> <pre>$($event['event_ip'])</pre>
<b>Группа:</b> <pre>$($event['event_usergroup'])</pre>
<b>Хост:</b> <pre>$($event['event_hostname'])</pre>
<pre>$($text)</pre>"

        Send-TelegramTextMessage -BotToken $botToken -ChatID $chatId -Message $messagetext
        sleep 2
    }

    if ($eventlist_sorted.Count -ne 0) 
    {
        ### count omitted events ###
        $omitted = $eventlist_ht.Count - $eventlist_sorted.Count

        ### inform users about omitted events ###
        Send-TelegramTextMessage -BotToken $botToken -ChatID $chatId -Message "Пропущено событий: <b>$($omitted)</b>"
    }

    if ($eventlist_ht.Count -ne 0) 
    {
        ### get the last event date (from xml data) ###
        if ($xmlContent.data.record.Count -eq 1) { $last_event_date = ($xmlContent.data.record.field  | ?{$_.name -eq "tmRiseTime"}).value }
        else { $last_event_date = ($xmlContent.data.record[$xmlContent.data.record.Count - 1].field  | ?{$_.name -eq "tmRiseTime"}).value }
        
        ### rewrite date ###
        if ($last_event_date -ne $null) { Out-File -Force -InputObject $last_event_date -Path "$($current_path)\last_event_date.txt" } 

        ### delete results xml file, replace it with an empty one ###
        ### see lines 32-34 ###
        New-Item -Path "$($current_path)" -Name "result_events.xml" -ItemType "file" -Force
    }
}