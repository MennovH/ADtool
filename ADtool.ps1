﻿#Created by: MennovH, 2021

[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[void] [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic")

$get_comp = Get-ADComputer $env:COMPUTERNAME -Properties OperatingSystem
if ($get_comp.OperatingSystem -like "*Windows Server 2008 R2*" -or $get_comp.OperatingSystem -like "*Windows 7*") {
    $MessageBody = "Due to the current version of the Operating system, some actions (e.g. unlocking AD users) may not work. The error message could look like:`n`n'Failed to unlock user account. Insufficient access rights to perform the operation.'`n`nIn order to fix this, one must upgrade the operating system, or install a hotfix from Microsoft. Otherwise, it's necessary to perform these actions via Active Directory..."
    $MessageTitle = "Information"
    [Microsoft.VisualBasic.Interaction]::MsgBox($MessageBody,'OkOnly,SystemModal,Critical',$MessageTitle) | Out-Null
}

if (!(Test-Path -Path ".\config.ini")) {
    $config = New-Item -Path ".\config.ini" -ItemType file
    $adm = "!"
} else {
    $adm = (Get-Content ".\config.ini" -Filter "[#" | Where-Object {($_.Contains("[#") -and $_.Length -gt 3)})
}

Add-Type -Assembly System.Drawing
if (Test-Path .\images) {
    Get-ChildItem .\images -Filter *.png | 
    Foreach-Object {
        $t = "$((Get-Culture).TextInfo.ToTitleCase($_.BaseName))Image"
        if (!(Test-Path variable:$t)){
        New-Variable -Name "$t" -Value ([System.Drawing.Image]::FromFile($($_.FullName)))
        }
    }
}

function save {
    $results = New-Object System.Collections.Generic.Dictionary"[Int,String]"
    $errors = New-Object System.Collections.Generic.Dictionary"[Int,String]"
    $table = @()
    if ($SaveButton.Text.ToLower().Contains('update')) {
        $removelist = $addlist = @()
        foreach($i in $CurrentRoles.Rows) {
            $exists = $false
            foreach($j in $BackupRoles.Rows) {
                if ($i.Cells['Group'].Value -eq $j.Cells['Group'].Value) {
                    $exists = $true
                    break
                }
            }
            if (!$exists) {
                $addlist += $i.Cells['Group'].Value
            }
        }
        foreach($i in $BackupRoles.Rows) {
            $exists = $false
            foreach($j in $CurrentRoles.Rows) {
                if ($i.Cells['Group'].Value -eq $j.Cells['Group'].Value) {
                    $exists = $true
                    break
                }
            }
            if (!$exists) {
                $removelist += $i.Cells['Group'].Value
            }
        }
        if ($removelist.Count -gt 0 -or $addlist.Count -gt 0) {
            $MessageBody = "Proceed with the following role update(s)?`n`nAdd ($($addlist.Count))" + $(if($addlist.Count -gt 0) {":`n$($addlist | Out-String)"} else {"`n"}) + "`nRemove ($($removelist.Count))" + $(if($removelist.Count -gt 0) {":`n$($removelist | Out-String)"})
            $MessageTitle = "Confirm choice"
            $Result = [Microsoft.VisualBasic.Interaction]::MsgBox($MessageBody,'YesNo,DefaultButton2,SystemModal,Critical',$MessageTitle)
            if ($Result -eq "Yes") {
                $arrayJobs = @()
                foreach($group in $addlist){
                    $arrayJobs += (Start-Job -Name "+$($group)" -ScriptBlock {param($group, $member); Add-ADGroupMember -Identity $group -Members $member} -ArgumentList $group, $UsernameTextbox.Text)
                }
                foreach($group in $removelist){
                    $arrayJobs += (Start-Job -Name "-$($group)" -ScriptBlock {param($group, $member); Remove-ADGroupMember -Identity $group -Members $member -Confirm:$false} -ArgumentList $group, $UsernameTextbox.Text)
                }
                $complete = $false
                while (-not $complete) {
                    $arrayJobsInProgress = $arrayJobs | Where-Object { $_.State -match ‘running’ }
                    if (-not $arrayJobsInProgress) {$complete = $true}
                }
                foreach($j in $arrayJobs) {
                    try{
                        Receive-Job -Job $j -ErrorAction Stop;
                        $name = $j.Name.Substring(1)
                        $results.Add($results.Count + 1,"$($j.Name.Substring(0,1).Replace("+", "Added to").Replace("-", "Removed from ")) '$($name)'")
                        $table += [Pscustomobject]@{Result = "Success";Task = "$($j.Name.Substring(0,1).Replace("+", "Add to").Replace("-", "Remove from ")) '$($name)'";Error = ""}

                    } catch {
                        $results.Add($results.Count + 1,"$($j.Name.Substring(0,1).Replace("+", "Failed to add to").Replace("-", "Failed to remove from ")) '$($name)'")
                        $errors.Add($errors.Count + 1, "$($n):`n$($_)")
                        $table += [Pscustomobject]@{Result = "Fail";Task = "$($j.Name.Substring(0,1).Replace("+", "Add to").Replace("-", "Remove from ")) '$($name)'";Error = "$_"}
                    }
                }
            }
        }
    }
    #Get-ADComputer -Identity "LT54045" -Properties * Enabled OperatingSystem PasswordExpired PasswordNeverExpires PasswordNotRequired isCriticalSystemObject
    $StatusLabel.BackColor = "Transparent"
    $StatusLabel.ForeColor = "Black"
    $SaveButton.Visible = $false
    $StatusLabel.FlatAppearance.BorderSize = 0
    $StatusLabel.Text = "Processing..."
    $StatusLabel.Visible = $true
    try{
        if ($NewPasswordTextBox.Text.Length -gt 0) {
            if ($RestoreRadioButton.Checked -and $OldPasswordTextBox.Text.Length -gt 0) {
                #restore password
                $type = "restore"
                $job = (Start-Job -Name RestorePassword -ScriptBlock {param($arg0,$arg1,$arg2); Set-ADAccountPassword -Identity $arg0 -OldPassword (ConvertTo-SecureString -AsPlainText $arg1 -Force) -NewPassword (ConvertTo-SecureString -AsPlainText $arg2 -Force)} -ArgumentList $UsernameTextbox.Text, $OldPasswordTextBox.Text, $NewPasswordTextBox.Text) | Wait-Job
            } else {
                #reset password
                $type = "reset"
                $job = (Start-Job -Name ResetPassword -ScriptBlock {param($arg0,$arg1); Set-ADAccountPassword -Identity $arg0 -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $arg1 -Force)} -ArgumentList $UsernameTextbox.Text, $NewPasswordTextBox.Text) | Wait-Job 
            }
            $status = try{Receive-Job -Job $job -ErrorAction Stop} catch {"$_"}
            if ($status -eq $null) {
                $results.Add($results.Count + 1, "Password $($type)$(if ($type -eq "restore"){"d"})")
                $table += [Pscustomobject]@{Result = "Success";Task = "Password $($type)";Error = ""}
            } else {
                $results.Add($results.Count + 1, "Failed to $($type) password"); $errors.Add($errors.Count + 1, "Password $($type):`n$($status)`n")
                $table += [Pscustomobject]@{Result = "Fail";Task = "Password $($type)";Error = "$status"}
            }
        }
        if ($SaveButton.Text.ToLower().Contains('enable')) {
            #enable user
            $job = Start-Job -Name EnableUser -ScriptBlock {param($arg0); Enable-ADAccount -Identity $arg0} -ArgumentList $UsernameTextbox.Text | Wait-Job
            $status = try{Receive-Job -Job $job -ErrorAction Stop} catch {"$_"}
            if ($status -eq $null) {
                $results.Add($results.Count + 1, "Account enabled")
                $table += [Pscustomobject]@{Result = "Success";Task = "Enable account";Error = ""}
            } else {
                $results.Add($results.Count + 1, "Failed to enable account"); $errors.Add($errors.Count + 1, "Enable account:`n$($status)`n")
                $table += [Pscustomobject]@{Result = "Fail";Task = "Enable account";Error = "$status"}
            }
        }
        if ($SaveButton.Text.ToLower().Contains('disable')) {
            #disable user
            $job = Start-Job -Name DisableUser -ScriptBlock {param($arg0); Disable-ADAccount -Identity $arg0} -ArgumentList $UsernameTextbox.Text | Wait-Job
            $status = try{Receive-Job -Job $job -ErrorAction Stop} catch {"$_"}
            if ($status -eq $null) {
                $results.Add($results.Count + 1, "Account disabled")
                $table += [Pscustomobject]@{Result = "Success";Task = "Disable account";Error = ""}
            } else {
                $results.Add($results.Count + 1, "Failed to disable account"); $errors.Add($errors.Count + 1, "Disable account:`n$($status)`n")
                $table += [Pscustomobject]@{Result = "Fail";Task = "Disable account";Error = "$status"}
            }
        }
        if ($SaveButton.Text.ToLower().Contains('unlock') -or ($NewPasswordTextBox.Text.Length -gt 0 -and !$SaveButton.Text.ToLower().Contains('disable'))) {
            #unlock user
            $job = Start-Job -Name UnlockUser -ScriptBlock {param($arg0); Unlock-ADAccount -Identity $arg0} -ArgumentList $UsernameTextbox.Text | Wait-Job
            $status = try{Receive-Job -Job $job -ErrorAction Stop} catch {"$_"}
            if (!$SaveButton.Text.ToLower().Contains('unlock')) {
                $addition = " (in addition)"
            }
            if ($status -eq $null) {
                $results.Add($results.Count + 1, "Account unlocked$($addition)")
                $table += [Pscustomobject]@{Result = "Success"; Task = "Unlock account$($addition)";Error = ""}
            } else {
                $results.Add($results.Count + 1, "Failed to unlock account$($addition)"); $errors.Add($errors.Count + 1, "Unlock account$($addition):`n$($status)")
                $table += [Pscustomobject]@{Result = "Fail"; Task = "Unlock account$($addition)";Error = "$status"}
            }
        }
        #get user status
        $job = (Start-Job -Name CheckStatus -ScriptBlock {param($arg0); Get-ADUser -Identity $($arg0) -Properties * | Select LockedOut, Enabled, PasswordLastSet, PasswordExpired} -ArgumentList $UsernameTextbox.Text) | Wait-Job
        $status = try{Receive-Job -Job $job -ErrorAction Stop} catch {"$_"}

        $job = (Start-Job -Name GetPasswordPolicy -ScriptBlock {(Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days}) | Wait-Job
        $MaxPwdAge = try{Receive-Job -Job $job -ErrorAction Stop} catch {"$_"}

        $dgv.CurrentRow.Cells['Locked'].Value = $status.LockedOut
        $dgv.CurrentRow.Cells['Password last set'].Value = $status.PasswordLastSet

        if ($status.PasswordLastSet.Length -gt 0) {
            $dgv.CurrentRow.Cells['Password expires'].Value = [datetime]($dgv.CurrentRow.Cells['Password last set'].Value).AddDays($MaxPwdAge)
        } else {
            $dgv.CurrentRow.Cells['Password expires'].Value = $status.PasswordLastSet
        }
        $total = $results.Values | Out-string
        if ($errors.Count -gt 0 -and $total.Length -ne 0) {$total += "`n"}
        $total += $errors.Values | Out-string
        $total.Replace(": failed", ": failed*")
        if ($errors.Count -eq $results.Count) {
            $StatusLabel.ForeColor = "White"
            $StatusLabel.BackColor = "Red"
        } elseif ($errors.Count -gt 0) {
            $StatusLabel.ForeColor = "Black"
            $StatusLabel.BackColor = "Orange"
        } else {
            $StatusLabel.ForeColor = "Black"
            $StatusLabel.BackColor = "Lightgreen"
        }
        $StatusLabel.FlatAppearance.BorderSize = 1
        $StatusLabel.Text = "Show report"
        $StatusLabelTotal.Text = $total
        if ($total.Length -gt 0) {
            try {
                $path = ".\tasklog"
                If(!(test-path $path)) {
                        New-Item -ItemType Directory -Force -Path $path
                }
                $file_path = "$($UsernameTextbox.Text).txt"

                if (!(Test-Path -Path $(Join-Path -Path $path $file_path))) {
                    New-Item -Path $(Join-Path -Path $path $file_path) -ItemType File
                    $s = ""
                } else {
                    $s = "`r`n"
                }
                $t = "Task$(if ($results.Count -ne 1){"s"}) ($($results.Count))"
                $e = "Error$(if ($errors.Count -ne 1){"s"}) ($($errors.Count))"
                "$($s)$("#"*35) $((Get-Date).ToString("dd.MM.yyyy - HH.mm.ss")) $("#"*35)`r`n`r`n" + ($table | Format-Table -Wrap -Property @{e='Result';Width=10}, @{e='Task';label=$t;Width=40}, @{e='Error';label=$e;Width=100} | Out-String).Trim() | Out-File -FilePath $(Join-Path -Path $path $file_path) -Append
            } catch {}
        }
        $list = @($status.PasswordExpired, !$status.Enabled, $status.LockedOut)
        for ($i=0; $i -lt $list.Count; $i++){
            switch ($i) {
                0 {$col = "Password expires"}
                1 {$col = "Enabled"}
                2 {$col = "Locked"}
            }
            if ($list[$i] -and $list[$i] -ne $null) {
                $dgv.SelectedRows[0].Cells[$col].Style.BackColor = "Orange"
                $dgv.SelectedRows[0].Cells[$col].Style.ForeColor = "Black"
                $dgv.SelectedRows[0].Cells[$col].Style.SelectionBackColor = "Red"
                $dgv.SelectedRows[0].Cells[$col].Style.SelectionForeColor = "White"
            } else {
                $dgv.SelectedRows[0].Cells[$col].Style.BackColor = $dgv.SelectedRows[0].Cells['Name'].Style.BackColor
                $dgv.SelectedRows[0].Cells[$col].Style.ForeColor = $dgv.SelectedRows[0].Cells['Name'].Style.ForeColor
                $dgv.SelectedRows[0].Cells[$col].Style.SelectionBackColor = "Yellow"
                $dgv.SelectedRows[0].Cells[$col].Style.SelectionForeColor = "Blue"
            }
        }
    } catch {
        $StatusLabel.BackColor = "Red"
        $StatusLabel.ForeColor = "White"
        $StatusLabel.Text = "Show report"
        $StatusLabel.FlatAppearance.BorderSize = 1
        $StatusLabelTotal.Text = $Error[0]
    }
}

function switchview {
    $list = @($UserGrid, $UserRolesGrid, $UserPropertiesGrid, $GroupGrid)
    switch ($UsernameLabel.Text) {
        "Object" {
            #user will be selected
            $UsernameLabel.Text = "User"
            $AdminUpdate.Visible = $UserTypeCheckBox.Visible = $true
            $SearchGroupTextBox.Visible = $false
            $SearchUserTextBox.Visible = $true
            if ($UsernameTextbox.Text.Length -gt 0) {$InfoButton.Visible = $RoleButton.Visible = $true} else {$InfoButton.Visible = $RoleButton.Visible = $false}
            $GroupGrid.Visible = $false; $UserGrid.Visible = $true
            $GroupsTextbox.Visible = $UserRolesGrid.Visible = $false
            $UsernameTextbox.Visible = $true
            $SearchUserTextBox.Focus()
        }
        "Printer" {$UsernameLabel.Text = "Object"}
        "Group" {$UsernameLabel.Text = "Printer"}
        "User" {
                
            $UsernameLabel.Text = "Group"
            $AdminUpdate.Visible = $UserTypeCheckBox.Visible = $InfoButton.Visible = $RoleButton.Visible = $false
            $SearchUserTextBox.Visible = $UserRolesGrid.Visible = $false
            $SearchGroupTextBox.Visible = $true
            $UserGrid.Visible = $false; $GroupGrid.Visible = $true
            $UsernameTextbox.Visible = $false
            $GroupsTextbox.Visible = $true
            $SearchGroupTextBox.Focus()
        }
    }
}

function check {
    $vars = @($OldPasswordTextBox, $NewPasswordTextBox, $SaveButton)
    if ($UsernameTextbox.Text.Length -eq 0) {
        foreach($i in $vars) {
            $i.Visible = $false
        }
        $SaveButton.Text = ""
        $RestoreRadioButton.Visible = $ResetRadioButton.Visible = $RoleButton.Visible = $InfoButton.Visible = $UserRolesGrid.Visible = $UserPropertiesGrid.Visible = $EnableCheckBox.Visible = $false
        if (!(Test-Path variable:$userrolesImage)){
            $RoleButton.Image = $userrolesImage
            $RoleButton.Text = ""
        } else {
            $RoleButton.Text = "R"
        }
        $RoleButton.ForeColor = "Black"
        $dgv.Visible = $true
    } else {
        if ($dgv.SelectedRows[0].Cells['Locked'].Value -eq $false) {$locked = $false} else {$locked = $true}

        $RoleButton.Visible = $InfoButton.Visible = $EnableCheckBox.Visible = $true
        $RestoreRadioButton.Visible = $ResetRadioButton.Visible = $true
        if ($RestoreRadioButton.Checked) {
            for ($i = 0; $i -lt 3; $i++) {if ($i -ne 2) {$vars[$i].Visible = $true} else {$vars[$i].Visible = $false}}
            if (!$locked -and $vars[0].Text.Length -eq 0 -and $vars[1].Text.Length -eq 0) {$res = 1} #invisible
            if ($locked -and $vars[0].Text.Length -eq 0 -and $vars[1].Text.Length -eq 0) {$res = 2} #unlock
            if ($vars[0].Text.Length -gt 0 -and $vars[1].Text.Length -gt 0) {$res = 3} #restore
        } else {
            for ($i = 0; $i -lt 3; $i++) {if ($i -gt 0 -and $i -ne 2) {$vars[$i].Visible = $true} else {$vars[$i].Visible = $false}}
            if (!$locked -and $vars[1].Text.Length -eq 0) {$res = 1} #invisible
            if ($locked -and $vars[1].Text.Length -eq 0) {$res = 2} #unlock
            if ($vars[1].Text.Length -gt 0) {$res = 4} #reset
        }
        if ($EnableCheckBox.Checked -and $EnableCheckBox.Text -eq "Disable" -and $res -le 2) {$res = 5}
        if ($EnableCheckBox.Checked -and $EnableCheckBox.Text -eq "Enable" -and $res -eq 1) {$res = 5}
    }
    switch ($res) {
        1 {$SaveButton.Visible = $false}
        2 {$SaveButton.Visible = $true; $SaveButton.Text = "Unlock"; if ($EnableCheckBox.Checked) {$SaveButton.Text += " and $($EnableCheckBox.Text.toLower())"}}
        3 {$SaveButton.Visible = $true; $SaveButton.Text = "Restore password"; if ($locked -and !$EnableCheckBox.Checked -and $EnableCheckBox.Text -eq "Disable") {$SaveButton.Text += " and unlock"} elseif ($EnableCheckBox.Checked) {$SaveButton.Text += " and $($EnableCheckBox.Text.toLower())"}}
        4 {$SaveButton.Visible = $true; $SaveButton.Text = "Reset password"; if ($locked -and !$EnableCheckBox.Checked -and $EnableCheckBox.Text -eq "Disable") {$SaveButton.Text += " and unlock"} elseif ($EnableCheckBox.Checked) {$SaveButton.Text += " and $($EnableCheckBox.Text.toLower())"}}
        5 {$SaveButton.Visible = $true; $SaveButton.Text = $EnableCheckBox.Text}
    }

    $change = $false
    foreach ($i in $CurrentRoles.Rows) {
        foreach ($j in $BackupRoles.Rows) {
            $in = $false
            if ($i.Cells['Group'].Value -eq $j.Cells['Group'].Value){
                $in = $true
                break
            }
        }
        if (!$in) {
            $change = $true
            break
        }
    }
    if ($CurrentRoles.RowCount -ne $BackupRoles.RowCount) {
        $change = $true
    }
    if ($change) {
        $SaveButton.Text = $SaveButton.Text.Replace(" and",", ")
        if ($SaveButton.Visible){
            $SaveButton.Text += " and update"
        } else {
            $SaveButton.Visible = $true
            $SaveButton.Text = "Update"
        }
    }
    $StatusLabel.BackColor = "Transparent"
    $StatusLabel.Text = ""
    $StatusLabel.Visible = $false
}

function row_color ($item) {
    $dgv.Rows[$dgv.RowCount -1].Cells[$item].Style.BackColor = "Orange"
    $dgv.Rows[$dgv.RowCount -1].Cells[$item].Style.ForeColor = "Black"
    $dgv.Rows[$dgv.RowCount -1].Cells[$item].Style.SelectionBackColor = "Red"
    $dgv.Rows[$dgv.RowCount -1].Cells[$item].Style.SelectionForeColor = "White"
}

function row_colors ($val) {
    for ($i=0;$i -lt $dgv.RowCount;$i++){
        if ($($i%2) -eq 1) {
            $dgv.Rows[$i].DefaultCellStyle.BackColor = $val
        } else {
            $dgv.Rows[$i].DefaultCellStyle.BackColor = "White"
        }
    }
}

function refresh {
    if ($SearchUserTextBox.Text.Replace("*","").Length -eq 0) {$SearchVal = "*"} else {$SearchVal = "*$($SearchUserTextBox.Text)*"}
    $UserRolesGrid.Visible = $UserPropertiesGrid.Visible = $false
    $UserGrid.Visible = $true
    if (!(Test-Path variable:$UserinfoImage)){
        $InfoButton.Image = $UserinfoImage
    } else {
        $InfoButton.Text = " I"
    }
    $UserGrid_QueryLabel.Text = "Preparing fetch"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $stopwatch.Start()
    $dgv.Rows.Clear()
    $BackupRoles.Rows.Clear()
    $CurrentRoles.Rows.Clear()
    $dgv.Rows.Clear()
    $UsernameTextbox.Text = ""
    $EnableCheckBox.Text = ""
    $EnableCheckBox.Checked = $false
    check
    $i = 0
    if ($BlockLabel.Text -ne "x") {
        $MaxPwdAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
        try{
            if (Test-Path -Path ".\config.ini") {
                $adm = (Get-Content ".\config.ini" -Filter "[#" | Where-Object {($_.Contains("[#") -and $_.Length -gt 3)})
            } elseif ($UserTypeCheckBox.Text -ne "!" -and $UserTypeCheckBox.Text.Length -gt 0) {
                $adm = $UserTypeCheckBox.Text
            }
            if ($adm.Length -gt 0) {
                $PrefixSuffix = $($adm.Substring(4, $adm.Length -4).Replace("[$]",""))
                if ($PrefixSuffix.Length -gt 0) {
                    if ($adm.Substring(0, 4) -eq "[#l]") {
                        $PrefixSuffix = "$($PrefixSuffix)*"
                    } elseif ($adm.Substring(0,4) -eq "[#r]") {
                        $PrefixSuffix = "*$($PrefixSuffix)"
                    } elseif ($adm.Substring(0,4) -eq "[#c]") {
                        $PrefixSuffix = "*$($PrefixSuffix)*"
                    }
                }
            }
            if ($UserTypeCheckBox.Checked) {
                $job = Start-Job -Name fetch -ScriptBlock {param($arg0,$arg1); Get-ADUser -Filter "GivenName -like '*' -and SamAccountName -like '$($arg0)' -and (Name -like '$($arg1)' -or DisplayName -like '$($arg1)' -or SamAccountName -like '$($arg1)')" -Properties Name, DisplayName, SamAccountName, LockedOut, PasswordExpired, PasswordLastSet, GivenName} -ArgumentList $PrefixSuffix,$SearchVal
            } else {
                $job = Start-Job -Name fetch -ScriptBlock {param($arg0); Get-ADUser -Filter "GivenName -like '*' -and (Name -like '$($arg0)' -or DisplayName -like '$($arg0)' -or SamAccountName -like '$($arg0)')" -Properties Name, DisplayName, SamAccountName, LockedOut, PasswordExpired, PasswordLastSet, GivenName} -ArgumentList $SearchVal
            }
            while ( $job.State -eq [System.Management.Automation.JobState]::Running ) {
                $UserGrid_QueryLabel.Text = "Fetching data ($($stopwatch.Elapsed.Minutes * 60 + $stopwatch.Elapsed.Seconds))"
                $UserGrid_QueryLabel.Refresh()
            }
            $users = Receive-Job -Job $job
        }catch{$UserGrid_QueryLabel.Text = "Error occurred: $Error[0]"; write-host $Error[0]}
        if ($users) {
            foreach($i in $users) {
                if (!$UserTypeCheckBox.Checked -and $i.SamAccountName -like $PrefixSuffix) {continue}
                try{
                    if ($i.PasswordLastSet.Length -gt 0) {
                        $dgv.Rows.Add($i.DisplayName,$i.Name,$i.SamAccountName,$i.LockedOut, $i.Enabled, [datetime]($i.PasswordLastSet).AddDays($MaxPwdAge), $i.PasswordLastSet)
                    } else {
                        $dgv.Rows.Add($i.DisplayName,$i.Name,$i.SamAccountName,$i.LockedOut, $i.Enabled, $i.PasswordLastSet, $i.PasswordLastSet)
                    }
                    if ($i.PasswordExpired -and $i.PasswordLastSet.Length -gt 0) {row_color "Password expires"}
                    if (!$i.Enabled) {row_color "Enabled"}
                    if ($i.LockedOut) {row_color "Locked"}
                    $dgv.AutoResizeRow($dgv.RowCount-1, [System.Windows.Forms.DataGridViewAutoSizeRowMode]::AllCellsExceptHeader)
                    $UserGrid_QueryLabel.Text = "Fetching data ($($stopwatch.Elapsed.Minutes * 60 + $stopwatch.Elapsed.Seconds))"
                    $UserGrid_QueryLabel.Refresh()
                } catch {Write-Host $Error}
            }
            $dgv.Sort($dgv.Columns['Username'],'Ascending')
            #row_colors "PaleTurquoise"
            $BlockLabel.Text = ""
            $dgv.FirstDisplayedScrollingRowIndex = 0
            $dgv.Refresh()
            if($DisplayButton.Text -eq "◨") {
                $dgv.CurrentCell = $dgv.Rows[0].Cells['Display name']
            } else {
                $dgv.CurrentCell = $dgv.Rows[0].Cells['Name']
            }
            $dgv.Rows[0].Selected = $true
            $UsernameTextbox.Text = $dgv.Rows[0].Cells['Username'].Value
            if ($dgv.Rows[0].Cells['Enabled'].Value -eq $true) {$EnableCheckBox.Text = "Disable"} else {$EnableCheckBox.Text = "Enable"}
        }
    }
    $stopwatch.Stop()
    $time = $($stopwatch.Elapsed.Minutes * 60 + $stopwatch.Elapsed.Seconds)
    if ($time -eq 1) {$time = "$($time) second"} else {$time = "$($time) seconds"}
    if ($UserGrid_QueryLabel.Text -like "Fetching*" -or $UserGrid_QueryLabel.Text -eq "Preparing fetch"){
        if ($dgv.RowCount -eq 1) {$UserGrid_QueryLabel.Text = "Fetched $($dgv.RowCount) row in $($time) - Query: `"$($SearchVal)`""} elseif ($BlockLabel.Text -ne "x") {$UserGrid_QueryLabel.Text = "Fetched $($dgv.RowCount) rows in $($time) - Query: `"$($SearchVal)`""} else {$UserGrid_QueryLabel.Text = "Enter a value and/or press enter to search user. Duration time depends on search value"; check}
    }
    $BlockLabel.Text = ""
}

function refresh_group {
    $BlockLabel.Text = "x"
    if ($SearchUserTextBox.Text.Replace("*","").Length -eq 0) {$SearchVal = "*"} else {$SearchVal = "*$($SearchUserTextBox.Text)*"}    
    if (!(Test-Path variable:$GroupinfoImage)){$InfoGroupButton.Image = $GroupinfoImage} else {$InfoGroupButton.Text = " I"}
    $GroupGrid_QueryLabel.Text = "Preparing fetch"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $stopwatch.Start()
    $BackupGroups.Rows.Clear()
    $AllGroups.Rows.Clear()
    $AllMembers.Rows.Clear()
    $GroupsTextbox.Text = ""
    $BlockLabel.Text = "y"
    $i = 0
    if ($SearchGroupTextBox.Text.Length -eq 0) {$SearchVal = "*"} else {$SearchVal = "*$($SearchGroupTextBox.Text)*"}
    $job = Start-Job -Name fetch -ScriptBlock {param($arg0); Get-ADGroup  -Filter "SamAccountName -like '$($arg0)' -or Description -like '$($arg0)'" -Properties SamAccountName, Description, GroupCategory, ManagedBy } -ArgumentList $SearchVal
    if ($SearchGroupTextBox.Text.Length -gt 2){
    while((Get-Job -State Running | Where-Object {$_.Name -eq "fetch"}).Count -gt 0) {
        $i++
        $GroupGrid_QueryLabel.Text = "Fetching data `($($i)`)"
        Start-Sleep -Milliseconds 900
    }} else {Wait-Job -Job $job}
    $status = try{Receive-Job -Job $job -ErrorAction Stop} catch {"$_"}
    if ($status) {
        foreach ($i in $status) {
            $AllGroups.Rows.Add($i.SamAccountName,$i.Description,$i.GroupCategory.Value,$i.ManagedBy)
        }
        $AllGroups.Sort($AllGroups.Columns['Group'],'Ascending')
        $AllGroups.FirstDisplayedScrollingRowIndex = 0
        $AllGroups.Refresh()
        $AllGroups.CurrentCell = $AllGroups.Rows[0].Cells['Group']
        $AllGroups.Rows[0].Selected = $true
        $GroupsTextbox.Text = $AllGroups.Rows[0].Cells['Group'].Value
    }
    $stopwatch.Stop()
    $time = $($stopwatch.Elapsed.Minutes * 60 + $stopwatch.Elapsed.Seconds)
    if ($time -eq 1) {$time = "$($time) second"} else {$time = "$($time) seconds"}
    if ($GroupGrid_QueryLabel.Text -like "Fetching*" -or $GroupGrid_QueryLabel.Text -eq "Preparing fetch"){
        if ($AllGroups.RowCount -eq 1) {$GroupGrid_QueryLabel.Text = "Fetched $($AllGroups.RowCount) row in $($time) - Query: `"$($SearchVal)`""} elseif ($BlockLabel.Text -ne "x") {$GroupGrid_QueryLabel.Text = "Fetched $($AllGroups.RowCount) rows in $($time) - Query: `"$($SearchVal)`""} else {$GroupGrid_QueryLabel.Text = "Enter a value and/or press enter to search user. Duration time depends on search value"}
    }
    $BlockLabel.Text = ""
}
function fetch_info {
    $UserProperties.Rows.Clear()
    $job = Start-Job -Name fetch -ScriptBlock {param($arg0); Get-ADUser -Identity $arg0 -Properties GivenName,Surname,DisplayName,Name,SamAccountName,EmployeeID,
    EmployeeNumber,employeeType,City,EmailAddress,DoesNotRequirePreAuth,Enabled,LockedOut,LockoutTime,LogonCount,LogonWorkstations,mail,mailNickname,Manager,MobilePhone,Modified,
    ModifyTimeStamp,Office,OfficePhone,Organization,PasswordExpired,PasswordLastSet,PasswordNeverExpires,PasswordNotRequired,physicalDeliveryOfficeName,PostalCode,
    ProtectedFromAccidentalDeletion,ProfilePath,showInAddressBook,SmartcardLogonRequired,State,StreetAddress,targetAddress,UserPrincipalName,whenCreated,whenChanged,HomeDirectory,
    HomeDrive,HomePhone,Fax} -ArgumentList $UsernameTextBox.Text | Wait-Job
    $status = try{Receive-Job -Job $job -ErrorAction Stop} catch {"$_"}

    $list = @(@("Given Name",$status.GivenName),
            @("Surname",$status.Surname),
            @("Display name",$status.DisplayName),
            @("Name",$status.Name),
            @("Username",$status.SamAccountName),
            @("User principal name",$status.UserPrincipalName),
            @("Employee ID",$status.EmployeeID),
            @("Employee number",$status.EmployeeNumber),
            @("Employee type",$status.EmployeeType),
            @("Manager",$status.Manager),
            @("Home phone",$status.HomePhone),
            @("Mobile phone",$status.MobilePhone),
            @("Office phone",$status.OfficePhone),
            @("Email address",$status.EmailAddress),
            @("Mail",$status.mail),
            @("Mail nickname",$status.mailNickname),
            @("Home directory",$status.HomeDirectory),
            @("Home drive",$status.HomeDrive),
            @("Organization",$status.Organization),
            @("Office",$status.Office),
            @("Physical delivery office name",$status.physicalDeliveryOfficeName),
            @("State",$status.State),
            @("Street address",$status.StreetAddress),
            @("Postal code",$status.PostalCode),
            @("City",$status.City),
            @("Created",$status.whenCreated),
            @("Changed",$status.whenChanged),
            @("Enabled",$status.Enabled),
            @("Fax",$status.Fax),
            @("Locked",$status.LockedOut),
            @("Lockout time",$status.LockoutTime),
            @("Logon count",$status.LogonCount),
            @("No pre-auth required",$status.DoesNotRequirePreAuth),
            @("Password expired",$status.PasswordExpired),
            @("Password last set",$status.PasswordLastSet),
            @("Password never expires",$status.PasswordNeverExpires),
            @("Password not required",$status.PasswordNotRequired),
            @("Profile path",$status.ProfilePath),
            @("Protected from accidental deletion",$status.ProtectedFromAccidentalDeletion),
            @("Modified",$status.Modified),
            @("Modify timestamp",$status.ModifyTimeStamp),
            @("Logon workstations",$status.LogonWorkstations),
            @("Show in address book",$status.showInAddressBook),
            @("Smartcard logon required",$status.SmartcardLogonRequired),
            @("Target address",$status.targetAddress))

    foreach($i in $list) {
        if ($i[1] -is [Object[]] -or $i[1] -is [System.Collections.ArrayList]) {
            $UserProperties.Rows.Add($i[0], ($i[1] | Out-String))
        } elseif ($i[1] -ne $null) {
            $UserProperties.Rows.Add($i[0], "$($i[1])")
        } else {$UserProperties.Rows.Add($i[0], "")}
    }
    foreach($i in $CheckBoxGrid.Rows){
        foreach($j in $UserProperties.Rows) {
            if ($j.Cells[0].Value -eq $i.Cells[1].Value) {
                $j.Visible = $i.Cells[0].Value
                break
            }
        }
    }
    foreach($i in $UserProperties.Rows) {
        if ($i.Visible) {
            $i.Selected = $true
            break
        }
    }
    $CheckBoxButton.Visible = $false
}

function memberof {
    if ($CurrentRoles.RowCount -eq 0) {
        $CurrentRoles.Rows.Clear()
        $BackupRoles.Rows.Clear()
    }
    $UserGrid.Visible = $UserPropertiesGrid.Visible = $false
    $UserRolesGrid.Visible = $true

    if ($CurrentRoles.RowCount -eq 0) {
        $UserRolesGridStatusLabel.Text = ""
        $UserRolesGridStatusLabel.BackColor = "Transparent"
        $job = Start-Job -Name fetch -ScriptBlock {param($arg0); $(Get-ADUser -Filter "SamAccountName -eq '$($arg0)'" -Properties MemberOf).memberof | Get-ADGroup -Properties SamAccountName, Description, GroupCategory, ManagedBy} -ArgumentList $UsernameTextbox.Text | Wait-Job
        $status = try{Receive-Job -Job $job -ErrorAction Stop} catch {"$_"}
        if ($status) {
            foreach ($i in $status) {
                $CurrentRoles.Rows.Add($i.SamAccountName,$i.Description,$i.GroupCategory.Value,$i.ManagedBy)
                $BackupRoles.Rows.Add($i.SamAccountName,$i.Description,$i.GroupCategory.Value,$i.ManagedBy)
            }
            $BackupRoles.Refresh()
            $CurrentRoles.Sort($CurrentRoles.Columns['Group'],'Ascending')
            $CurrentRoles.FirstDisplayedScrollingRowIndex = 0
            $CurrentRoles.Refresh()
            $CurrentRoles.CurrentCell = $CurrentRoles.Rows[0].Cells['Group']
            $CurrentRoles.Rows[0].Selected = $true
        }
    }
    $BlockLabel.Text = ""
}

function set-admin-prefix {
    if ($AdminTextBox.Text.Length -gt 0){
        $PrefixSuffix = $AdminTextBox.Text.Trim("*")
        $AdminTextBox.Text = $PrefixSuffix
        if ($LeftRadioButton.Checked) {$UserTypeCheckBox.Text = "$($AdminTextBox.Text)*"; $adm = "[#l]$($PrefixSuffix)";}
        if ($CenterRadioButton.Checked) {$UserTypeCheckBox.Text = $adm = "*$($AdminTextBox.Text)*";$adm = "[#c]$($PrefixSuffix)";}
        if ($RightRadioButton.Checked) {$UserTypeCheckBox.Text = $adm = "*$($AdminTextBox.Text)";$adm = "[#r]$($PrefixSuffix)";}
        
        $list = @()
        if ($adm.Length -gt 0) {$list += $adm}
        foreach ($i in $CheckBoxGrid.Rows) {
            $list += [int]$i.Cells[0].Value
        }
        Set-Content -Path ".\config.ini" -Value ($list | Out-String)
        if (($($UserTypeCheckBox.Text -ne "!" -and $UserTypeCheckBox.Checked) -or !$UserTypeCheckBox.Checked)) {if (!$UserTypeCheckBox.Checked -and $SearchUserTextBox.Text.Length -eq 0) {$BlockLabel.Text = "x"};refresh; $BlockLabel.Text = ""; $SearchUserTextBox.Focus()}
    }
}

function start-script{
    $form = New-Object System.Windows.Forms.Form
    $form.Text = ”ADtool”
    $form.StartPosition = "CenterScreen"
    $Font = New-Object System.Drawing.Font("Calibri",11)
    $form.Font = $Font
    $form.AutoSize = $true
    $form.Width = 744
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false

    $UserGrid = New-Object System.Windows.Forms.GroupBox
    $UserGrid.Size=New-Object System.Drawing.Size(400,400)
    $UserGrid.Width = $form.Width
    $UserGrid.Dock = 'Top'
    $form.Controls.Add($UserGrid)

    $UserRolesGrid = New-Object System.Windows.Forms.GroupBox
    $UserRolesGrid.Size=New-Object System.Drawing.Size($UserGrid.Size)
    $UserRolesGrid.Visible = $false
    $UserRolesGrid.Dock = 'Top'
    $form.Controls.Add($UserRolesGrid)
   
    $UserPropertiesGrid = New-Object System.Windows.Forms.GroupBox
    $UserPropertiesGrid.Size=New-Object System.Drawing.Size($UserGrid.Size)
    $UserPropertiesGrid.Visible = $false
    $UserPropertiesGrid.Dock = 'Top'
    $form.Controls.Add($UserPropertiesGrid)

    $CopyButton = New-Object System.Windows.Forms.Label
    $CopyButton.Location = New-Object System.Drawing.Size($((($UserGrid.Width-264)*3/4)-30),$($UserPropertiesGrid.Top +4))
    $CopyButton.Size = New-Object System.Drawing.Size(20,20)
    if (!(Test-Path variable:$copyImage)){
        $CopyButton.Image = $copyImage
    } else {
        $CopyButton.Text = "C"
    }
    $CopyButton.Image = $copyImage
    $CopyButton.Visible = $false
    $CopyButton.Cursor = "Hand"
    $CopyButton.Add_Click({
        (Write-Output $UserProperties.SelectedRows[0].Cells['Value'].Value) | Set-Clipboard
        $CopyButton.Visible = $false
    })
    $UserPropertiesGrid.Controls.Add($CopyButton)
    $CopyButton.BringToFront()
    
    $PasteButton = New-Object System.Windows.Forms.Label
    $PasteButton.Location = New-Object System.Drawing.Size($($CopyButton.Right+4),$($UserPropertiesGrid.Top +4))
    $PasteButton.Size = New-Object System.Drawing.Size(20,20)
    $PasteButton.Image = $pasteImage
    $PasteButton.Cursor = "Hand"
    $PasteButton.Visible = $false
    if (!(Test-Path variable:$pasteImage)){
        $PasteButton.Image = $pasteImage
    } else {
        $PasteButton.Text = "P"
    }
    $PasteButton.Add_Click({
        $UserProperties.SelectedRows[0].Cells['Value'].Value = Get-Clipboard
        $PasteButton.Visible = $false
    })
    $UserPropertiesGrid.Controls.Add($PasteButton)
    $PasteButton.BringToFront()

    $GroupGrid = New-Object System.Windows.Forms.GroupBox
    $GroupGrid.Size=New-Object System.Drawing.Size($UserGrid.Size)
    $GroupGrid.Visible = $false
    $GroupGrid.Dock = 'Top'
    $form.Controls.Add($GroupGrid)

    $BottomPanel = New-Object System.Windows.Forms.Panel
    $BottomPanel.Location = New-Object System.Drawing.Size($($dgv.Right + 2),0)
    $BottomPanel.Size = New-Object System.Drawing.Size(744, 29)
    $BottomPanel.Dock = "Top"
    $BottomPanel.BackColor = "Transparent"
    $form.Controls.Add($BottomPanel)

    $UsernameLabel = New-Object System.Windows.Forms.Label
    $UsernameLabel.Location = New-Object System.Drawing.Size(4,5)
    $UsernameLabel.Size = New-Object System.Drawing.Size(50,24)
    #$UsernameLabel = New-Object System.Windows.Forms.Button
    #$UsernameLabel.Location = New-Object System.Drawing.Size(0, 2)
    #$UsernameLabel.Size = New-Object System.Drawing.Size(55,25)
    #$UsernameLabel.Font = New-Object System.Drawing.Font("Calibri",10.5,[System.Drawing.FontStyle]::Regular)
    #$UsernameLabel.ForeColor = "Blue"
    $UsernameLabel.Text = "User"
    $UsernameLabel.FlatStyle = "Flat"
    $UsernameLabel.BackColor = "Transparent"
    $UsernameLabel.Add_Click({
        #switchview
    })
    $BottomPanel.Controls.Add($UsernameLabel)
    
    $UsernameTextbox = New-Object System.Windows.Forms.TextBox
    $UsernameTextbox.Location = New-Object System.Drawing.Size($UsernameLabel.Right,2)
    $UsernameTextbox.Size = New-Object System.Drawing.Size($($UserGrid.Width/2-20-$UserNameLabel.Right),25)
    $UsernameTextbox.Text = ""
    $UsernameTextbox.Cursor = "Arrow"
    $UsernameTextbox.Font = New-Object System.Drawing.Font("Calibri",11,[System.Drawing.FontStyle]::Bold)
    $UsernameTextbox.BackColor = "LightGray"
    $UsernameTextbox.ReadOnly = $true
    $UsernameTextbox.TextAlign = "center"
    $UsernameTextbox.AllowDrop = $true
    $UsernameTextbox.Add_TextChanged({
        if ($BlockLabel.Text -ne "x") {
            $CurrentRoles.Rows.Clear()
            $BackupRoles.Rows.Clear()
            check
        }
        if ($UserRolesGrid.Visible -and $UsernameTextbox.Text.Length -gt 0) {memberof}
    })
    $BottomPanel.Controls.Add($UsernameTextbox)

    $GroupsTextbox = New-Object System.Windows.Forms.TextBox
    $GroupsTextbox.Location = New-Object System.Drawing.Size($UsernameLabel.Right,2)
    $GroupsTextbox.Size = New-Object System.Drawing.Size(450,$UsernameTextbox.Height)
    $GroupsTextbox.Text = ""
    $GroupsTextbox.Visible = $false
    $GroupsTextbox.Cursor = "Arrow"
    $GroupsTextbox.Font = New-Object System.Drawing.Font("Calibri",11,[System.Drawing.FontStyle]::Bold)
    $GroupsTextbox.BackColor = "LightGray"
    $GroupsTextbox.ReadOnly = $true
    $GroupsTextbox.TextAlign = "center"
    $GroupsTextbox.AllowDrop = $true
    $GroupsTextbox.Add_TextChanged({
        if ($BlockLabel.Text -ne "x") {
            $InfoGroupButton.Visible = $GroupsTextbox.Text.Length -gt 0
            $AllMembers.Rows.Clear()
        }
    })
    $BottomPanel.Controls.Add($GroupsTextbox)

    $InfoGroupButton = New-Object System.Windows.Forms.Label
    $InfoGroupButton.Location = New-Object System.Drawing.Size($($GroupsTextbox.Width - 30))
    $InfoGroupButton.Size = New-Object System.Drawing.Size(30,$UsernameTextbox.Height)
    $InfoGroupButton.Font = New-Object System.Drawing.Font("Calibri Light",13,[System.Drawing.FontStyle]::Bold)
    if (!(Test-Path variable:$GroupInfoImage)){
        $InfoGroupButton.Image = $GroupinfoImage
    } else {
        $InfoGroupButton.Text = " I"
    }
    $InfoGroupButton.ForeColor = "Blue"
    $InfoGroupButton.FlatStyle = "Flat"
    $InfoGroupButton.Cursor = "Hand"
    $InfoGroupButton.Visible = $false
    $InfoGroupButton.Add_Click({
        if($InfoGroupButton.Text -notlike "*⤴") {
            $InfoGroupButton.Image = $null
            if (!(Test-Path variable:$GroupInfoImage)){
                $InfoGroupButton.Text = "  ⤴";
            } else {
                $InfoGroupButton.Text = "⤴";
            }
            $AllGroups.Visible = $false

            $job = Start-Job -ScriptBlock {param($arg0); Get-ADGroupMember -Identity $arg0  | Where-Object {$_.ObjectClass -eq "User"} | Select Name, SamAccountName} -ArgumentList $GroupsTextbox.Text
            if ($SearchRoleTextBox.Text.Length -gt 2){
            $i = 0
            while((Get-Job -State Running | Where-Object {$_.Name -eq "fetch"}).Count -gt 0) {
                $i++
                $UserRolesGrid_QueryLabel.Text = "Fetching data `($($i)`)"
                Start-Sleep -Milliseconds 900
            }} else {Wait-Job -Job $job}
            $status = try{Receive-Job -Job $job -ErrorAction Stop} catch {"$_"}
            foreach ($i in $status) {
                $AllMembers.Rows.Add($i.Name, $i.SamAccountName)
            }
            $AllMembers.Visible = $NewMembers.Visible = $true
            $ToolTip.SetToolTip($InfoGroupButton, "Return")
        } else {
            $InfoGroupButton.Text = ""
            if (!(Test-Path variable:$GroupInfoImage)){
                $InfoGroupButton.Image = $GroupinfoImage
            } else {
                $InfoGroupButton.Text = " I"
            }
            $ToolTip.SetToolTip($InfoGroupButton, "Show group info")
            $AllMembers.Visible = $NewMembers.Visible = $false
            $AllGroups.Visible = $true;
            $SearchGroupTextBox.Focus()
        }
    })
    $GroupsTextbox.Controls.Add($InfoGroupButton)

    $dgv = New-Object System.Windows.Forms.DataGridView
    $dgv.Location = New-Object System.Drawing.Size(0,2)
    $dgv.ColumnCount = 7
    $dgv.DefaultCellStyle.SelectionBackColor = "Yellow"
    $dgv.DefaultCellStyle.SelectionForeColor = "Blue"
    $dgv.Columns[0].Name = "Display name"
    $dgv.Columns[1].Name = "Name"
    $dgv.Columns[2].Name = "Username"
    $dgv.Columns[3].Name = "Locked"
    $dgv.Columns[4].Name = "Enabled"
    $dgv.Columns[5].Name = "Password expires"
    $dgv.Columns[6].Name = "Password last set"
    $dgv.Columns['Display name'].MinimumWidth = $dgv.Columns['Name'].MinimumWidth = $dgv.Columns['Username'].MinimumWidth = 150
    $dgv.Columns['Name'].Visible = $false
    $dgv.Columns['Locked'].Width = $dgv.Columns['Enabled'].Width = 60
    $dgv.AllowUserToResizeColumns = $dgv.AllowUserToResizeRows = $dgv.AllowUserToResizeColumns = $dgv.AllowUserToAddRows = $dgv.MultiSelect = $dgv.RowHeadersVisible = $false;
    $dgv.ColumnHeadersHeightSizeMode = 1
    $dgv.EnableHeadersVisualStyles = 0
    $dgv.Width = $($UserGrid.Width)
    $dgv.ReadOnly = $true
    $dgv.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Calibri",11,[System.Drawing.FontStyle]::Bold)
    $dgv.BorderStyle = "None"
    $dgv.SelectionMode = 1
    $dgv.DefaultCellStyle.WrapMode = [System.Windows.Forms.DataGridViewTriState]::$true

    $UserGrid.Controls.Add($dgv)
    $dgv.Columns[0..6] | Foreach-Object{
        if ($_.Index -lt 3) {$param = "None"} elseif ($_.Index -lt 5) {$param = "AllCells"} else {$param = "Fill"}
        $_.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::$param
    }
    
    $dgv.Add_RowStateChanged({
        if ($BlockLabel.Text -eq "") {
            try{
                $EnableCheckBox.Text = ""
                $EnableCheckBox.Checked = $false
                $UsernameTextbox.Text = $dgv.SelectedRows[0].Cells['Username'].Value
                if ($dgv.SelectedRows[0].Cells['Enabled'].Value -eq $false) {$EnableCheckBox.Text = "Enable"} else {$EnableCheckBox.Text = "Disable"}
            }catch{}
        }
    })
    $dgv.Add_Sorted({
        row_colors "PaleTurquoise"
    })
    $dgv.Height = $($UserGrid.Height - 20)
    $UserPropertiesGrid.Height = $($dgv.Height + 20)
    
    $DisplayButton = New-Object System.Windows.Forms.Label
    $DisplayButton.Location = New-Object System.Drawing.Size(101,$($dgv.Top +3))
    $DisplayButton.Size = New-Object System.Drawing.Size(19,19)
    $DisplayButton.Text = "◨"
    $DisplayButton.FlatStyle = "Flat"
    $DisplayButton.Cursor = "Hand"
    $DisplayButton.Add_Click({
        if($DisplayButton.Text -eq "◨") {
            $dgv.Columns['Display name'].Visible = $false
            $dgv.Columns['Name'].Visible = $true
            $DisplayButton.Text = "◧"
        } else {
            $dgv.Columns['Display name'].Visible = $true
            $dgv.Columns['Name'].Visible = $false
            $DisplayButton.Text = "◨"
        }
    })
    $UserGrid.Controls.Add($DisplayButton)
    $DisplayButton.BringToFront()

    $SaveFilterSetting = New-Object System.Windows.Forms.Label
    $SaveFilterSetting.Location = New-Object System.Drawing.Size($($UserPropertiesGrid.Right - 130), 4)
    $SaveFilterSetting.Size = New-Object System.Drawing.Size(20, 20)
    $SaveFilterSetting.Image = $saveImage
    if (!(Test-Path variable:$saveImage)){
        $SaveFilterSetting.Image = $saveImage
    } else {
        $SaveFilterSetting.Text = "S"
    }
    $SaveFilterSetting.Visible = $false
    $SaveFilterSetting.Cursor = "Hand"
    $SaveFilterSetting.Add_Click({
        $list = @()
        if (Test-Path -Path ".\config.ini") {
            $adm = (Get-Content ".\config.ini" -Filter "[#" | Where-Object {($_.Contains("[#") -and $_.Length -gt 3)})
            if ($adm.Length -gt 0) {$list += $adm}
        }
        foreach ($i in $CheckBoxGrid.Rows) {
            $list += [int]$i.Cells[0].Value
        }
        Set-Content -Path ".\config.ini" -Value ($list | Out-String)
        $SaveFilterSetting.Visible = $CheckBoxButton.Visible = $false
    })
    $UserPropertiesGrid.Controls.Add($SaveFilterSetting)
    
    $CheckBoxButton = New-Object System.Windows.Forms.Label
    $CheckBoxButton.Location = New-Object System.Drawing.Size($($SaveFilterSetting.Left-24), 3)
    $CheckBoxButton.Size = New-Object System.Drawing.Size(20, 20)
    if (!(Test-Path variable:$filterImage)){
        $CheckBoxButton.Image = $filterImage
    } else {
        $CheckBoxButton.Text = "F"
    }
    $CheckBoxButton.Visible = $false
    $CheckBoxButton.Cursor = "Hand"
    $CheckBoxButton.Add_Click({
        foreach($i in $CheckBoxGrid.Rows){
            foreach($j in $UserProperties.Rows) {
                if ($j.Cells[0].Value -eq $i.Cells[1].Value) {
                    $j.Visible = $i.Cells[0].Value
                    break
                }
            }
        }
        $CheckBoxButton.Visible = $false
    })
    $UserPropertiesGrid.Controls.Add($CheckBoxButton)

    $UserProperties = New-Object System.Windows.Forms.DataGridView
    $UserProperties.DefaultCellStyle.SelectionBackColor = "Yellow"
    $UserProperties.DefaultCellStyle.SelectionForeColor = "Blue"
    $UserProperties.Location = New-Object System.Drawing.Size(0, $($dgv.Top))
    $UserProperties.Size = New-Object System.Drawing.Size($($dgv.Width-264),$($dgv.Height + 20))
    $UserProperties.ColumnCount = 2
    $UserProperties.Columns[0].Name = "Parent"
    $UserProperties.Columns[1].Name = "Value"
    $UserProperties.Columns['Parent'].ReadOnly = $true
    $UserProperties.AllowUserToResizeRows = $UserProperties.AllowUserToResizeColumns = $UserProperties.AllowUserToAddRows = $false
    $UserProperties.ColumnHeadersHeightSizeMode = 1
    $UserProperties.EnableHeadersVisualStyles = 0
    $UserProperties.RowHeadersVisible = $false
    $UserProperties.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Calibri",11,[System.Drawing.FontStyle]::Bold)
    $UserProperties.DefaultCellStyle.Font = New-Object System.Drawing.Font("Calibri",10,[System.Drawing.FontStyle]::Regular)
    $UserProperties.BorderStyle = "None"
    $UserProperties.SelectionMode = 1
    $UserProperties.MultiSelect = $false
    $UserPropertiesGrid.Controls.Add($UserProperties)

    $UserProperties.Columns[0..1] | Foreach-Object{
        $_.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
    }
    $UserProperties.Add_RowStateChanged({
        $CopyButton.Visible = $UserProperties.SelectedRows.Count -gt 0 -and $UserProperties.SelectedRows[0].Cells['Value'].Value.Length -gt 0
        $PasteButton.Visible = $UserProperties.SelectedRows.Count -gt 0 -and (Get-Clipboard).Length -gt 0
    })

    $CheckBoxGrid = New-Object System.Windows.Forms.DataGridView
    $CheckBoxGrid.DefaultCellStyle.SelectionBackColor = "Yellow"
    $CheckBoxGrid.DefaultCellStyle.SelectionForeColor = "Blue"
    $CheckBoxGrid.Location = New-Object System.Drawing.Size($($UserProperties.Right), $($dgv.Top))
    $CheckBoxGrid.Size = New-Object System.Drawing.Size(264,$UserProperties.Height)
    $CheckBoxColumn = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
    $CheckBoxColumn.width = 30
    $CheckBoxGrid.Columns.Add($CheckBoxColumn) | Out-Null
    $CheckBoxGrid.ColumnCount = 2
    $CheckBoxGrid.Columns[1].Name = "Item"
    $CheckBoxGrid.AllowUserToResizeRows = $CheckBoxGrid.AllowUserToResizeColumns = $CheckBoxGrid.AllowUserToAddRows = $false
    $CheckBoxGrid.ColumnHeadersHeightSizeMode = 1
    $CheckBoxGrid.EnableHeadersVisualStyles = 0
    $CheckBoxGrid.RowHeadersVisible = $false
    $CheckBoxGrid.ReadOnly = $true
    $CheckBoxGrid.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Calibri",11,[System.Drawing.FontStyle]::Bold)
    $CheckBoxGrid.DefaultCellStyle.Font = New-Object System.Drawing.Font("Calibri",10,[System.Drawing.FontStyle]::Regular)
    $CheckBoxGrid.BorderStyle = "None"
    $CheckBoxGrid.SelectionMode = 1
    $CheckBoxGrid.MultiSelect = $true
    $CheckBoxGrid.Add_Click({
        foreach($i in $CheckBoxGrid.SelectedRows){
            if ($i.Cells[0].Value -eq 1) {$i.Cells[0].Value = 0} else {$i.Cells[0].Value = 1}
        }
        $k = 0
        foreach($i in $CheckBoxGrid.Rows) {
            if ($i.Cells[0].Value -eq 1) {$k++}
        }
        if ($k -eq $CheckBoxGrid.RowCount) {$SelectItemCheckBox.CheckState = "Checked"} elseif ($k -eq 0) {$SelectItemCheckBox.CheckState = "Unchecked"} else {$SelectItemCheckBox.CheckState = "Indeterminate"}
        $SaveFilterSetting.Visible = $CheckBoxButton.Visible = $true
    })
    $UserPropertiesGrid.Controls.Add($CheckBoxGrid)
    $CheckBoxGrid.Columns[0].SortMode = "Programmatic"
    $CheckBoxGrid.Columns[1].SortMode = "Programmatic"
    $UserPropertiesGrid.Controls.Add($CheckBoxGrid)

    $list = @("Given name","Surname","Display name","Name","Username","Employee ID","Employee number","Employee type","City","Email address","No pre-auth required","Enabled",
    "Locked","Lockout time","Logon count","Logon workstations","Mail","Mail nickname","Manager","Mobile phone","Modified","Modify timeStamp","Office","Office phone","Organization",
    "Password expired","Password last set","Password never expires","Password not required","Physical delivery office name","Postal code","Protected from accidental deletion","Profile path",
    "Show in address book","Smartcard logon required","State","Street address","Target address","User principal name","Created","Changed","Home directory","Home drive","Home phone","Fax") | Sort-Object

    if (Test-Path -Path ".\config.ini") {
        $sellist = (Get-Content ".\config.ini" | Where-Object {($_ -eq "True" -or $_ -eq "False" -or $_ -eq 0 -or $_ -eq 1)})
    }
    if ($sellist.Length -eq 0) {
        $sellist = @(0,1,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,0,1,1,0,0,1,0,0,1,1,1,1,1,0,0,1,0,1,0,1,0,1,0,0,1,0)
    }
    $k=0
    foreach ($i in $list) {
        $CheckBox = New-Object System.Windows.Forms.CheckBox
        $CheckBoxGrid.Rows.Add($(if ($sellist[$k] -eq "True" -or $sellist[$k] -eq 1){1} else {0}),$i) | Out-Null
        $k++
    }

    $CheckBoxGrid.Columns[1] | Foreach-Object{
        $_.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
    }
    
    $CheckBoxGrid.Sort($CheckBoxGrid.Columns['Item'],'Ascending')

    $SelectItemCheckBox = New-Object System.Windows.Forms.CheckBox
    $SelectItemCheckBox.Location = New-Object System.Drawing.Size($($CheckBoxGrid.Location.X+9), $($dgv.Top + 5))
    $SelectItemCheckBox.Size = New-Object System.Drawing.Size(13, 13)
    $SelectItemCheckBox.Text = ""
    $SelectItemCheckBox.BackColor = "Green"
    if ($k -eq 0) {$SelectItemCheckBox.CheckState = "Unchecked"} elseif ($k -eq $CheckBoxGrid.RowCount) {$SelectItemCheckBox.CheckState = "Checked"} else {$SelectItemCheckBox.CheckState = "Indeterminate"}
    $SelectItemCheckBox.Add_Click({
        foreach($i in $CheckBoxGrid.Rows){
            $i.Cells[0].Value = $SelectItemCheckBox.Checked
        }
        $CheckBoxButton.Visible = $SaveFilterSetting.Visible = $true
    })
    $CheckBoxGrid.Columns[0].HeaderCell.Style.BackColor = "Transparent"

    $UserPropertiesGrid.Controls.Add($SelectItemCheckBox)
    $SelectItemCheckBox.BringToFront()

    $UserGrid_QueryLabel = New-Object System.Windows.Forms.Label
    $UserGrid_QueryLabel.Location = New-Object System.Drawing.Size(0, 380)
    $UserGrid_QueryLabel.Size = New-Object System.Drawing.Size($dgv.Width, 20)
    $UserGrid_QueryLabel.Text = "Enter a value and/or press enter to search user. Duration time depends on search value"
    $UserGrid_QueryLabel.ForeColor = "Yellow"
    $UserGrid_QueryLabel.BackColor = "Blue"
    $UserGrid.Controls.Add($UserGrid_QueryLabel)

    $UserRolesGrid_SearchLabel = New-Object System.Windows.Forms.Label
    $UserRolesGrid_SearchLabel.Location = New-Object System.Drawing.Size($UsernameLabel.Location.X, 16)
    $UserRolesGrid_SearchLabel.Size = New-Object System.Drawing.Size($UsernameLabel.Size)
    $UserRolesGrid_SearchLabel.Text = "Search"
    $UserRolesGrid_SearchLabel.TextAlign = "MiddleLeft"
    $UserRolesGrid_SearchLabel.BackColor = "Transparent"
    $UserRolesGrid.Controls.Add($UserRolesGrid_SearchLabel)

    $GroupGrid_QueryLabel = New-Object System.Windows.Forms.Label
    $GroupGrid_QueryLabel.Location = New-Object System.Drawing.Size(0, 380)
    $GroupGrid_QueryLabel.Size = New-Object System.Drawing.Size($dgv.Width, 20)
    $GroupGrid_QueryLabel.Text = "Enter a value and/or press enter to search group. Duration time depends on search value"
    $GroupGrid_QueryLabel.ForeColor = "Yellow"
    $GroupGrid_QueryLabel.BackColor = "Blue"
    $GroupGrid.Controls.Add($GroupGrid_QueryLabel)

    $SearchRoleTextBox = New-Object System.Windows.Forms.TextBox
    $SearchRoleTextBox.Location = New-Object System.Drawing.Size($UserRolesGrid_SearchLabel.Right,14)
    $SearchRoleTextBox.Size = New-Object System.Drawing.Size($UsernameTextbox.Width,30)
    $SearchRoleTextBox.Text = ""
    $SearchRoleTextBox.MaxLength = 25
    $SearchRoleTextBox.BackColor = "Lightblue"
    $SearchRoleTextBox.TextAlign = "center"
    $SearchRoleTextBox.AllowDrop = $true
    $SearchRoleTextBox.Add_TextChanged({
        forEach ($i in $CurrentRoles.Rows){
            $in = $false
            for ($j=0;$j -le 3;$j++) {
                if ("$($i.Cells[$j].Value)".ToLower().Contains($SearchRoleTextBox.Text)) {
                    $CurrentRoles.Rows[$i.Index].Selected = $true
                    $in = $true
                    break
                }
            }
            if (!$in) {$CurrentRoles.Rows[$i.Index].Selected = $false}
        }
        forEach ($i in $AllRoles.Rows){
            $in = $false
            for ($j=0;$j -le 3;$j++) {
                if ("$($i.Cells[$j].Value)".ToLower().Contains($SearchRoleTextBox.Text)) {
                    $AllRoles.Rows[$i.Index].Selected = $true
                    $in = $true
                    break
                } else {
                    $AllRoles.Rows[$i.Index].Selected = $false
                }
            }
            if (!$in) {$AllRoles.Rows[$i.Index].Selected = $false}
        }
    })
    $SearchRoleTextBox.Add_KeyDown({
        if ($_.KeyCode -eq "Enter"){
            $UserRolesGrid_QueryLabel.Text = "Preparing fetch"
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $stopwatch.Start()
            $AllRoles.Rows.Clear()
            $form.Update()
            if ($SearchRoleTextBox.Text.Length -lt 3) {
                $MessageBody = "This query could take more than 2 minutes!`n`nContinue?"
                $MessageTitle = "Confirm choice"
                $Result = [Microsoft.VisualBasic.Interaction]::MsgBox($MessageBody,'OkCancel,DefaultButton2,SystemModal,Critical',$MessageTitle)
                if ($Result -eq "Cancel") {return}
            }
            if ($SearchRoleTextBox.Text.Length -eq 0) {$SearchVal = "*"} else {$SearchVal = "*$($SearchRoleTextBox.Text)*"}
            $job = Start-Job -Name fetch -ScriptBlock {param($arg0); Get-ADGroup  -Filter "SamAccountName -like '$($arg0)' -or Description -like '$($arg0)'" -Properties SamAccountName, Description, GroupCategory, ManagedBy } -ArgumentList $SearchVal
            if ($SearchRoleTextBox.Text.Length -gt 2){
            $i = 0
            while((Get-Job -State Running | Where-Object {$_.Name -eq "fetch"}).Count -gt 0) {
                $i++
                $UserRolesGrid_QueryLabel.Text = "Fetching data `($($i)`)"
                Start-Sleep -Milliseconds 900
            }} else {Wait-Job -Job $job}
            $status = try{Receive-Job -Job $job -ErrorAction Stop} catch {"$_"}
            if ($status) {
                foreach ($i in $status) {
                    $AllRoles.Rows.Add($i.SamAccountName,$i.Description,$i.GroupCategory.Value,$i.ManagedBy)
                }
                $AllRoles.Sort($AllRoles.Columns['Group'],'Ascending')
                $AllRoles.FirstDisplayedScrollingRowIndex = 0
                $AllRoles.Refresh()
                $AllRoles.CurrentCell = $AllRoles.Rows[0].Cells['Group']
                $AllRoles.Rows[0].Selected = $true
            }
            $stopwatch.Stop()
            $time = $($stopwatch.Elapsed.Minutes * 60 + $stopwatch.Elapsed.Seconds)
            if ($time -eq 1) {$time = "$($time) second"} else {$time = "$($time) seconds"}
            if ($UserRolesGrid_QueryLabel.Text -like "Fetching*" -or $UserRolesGrid_QueryLabel.Text -eq "Preparing fetch"){
                if ($AllRoles.RowCount -eq 1) {$UserRolesGrid_QueryLabel.Text = "Fetched $($AllRoles.RowCount) row in $($time) - Query: `"$($SearchVal)`""} elseif ($BlockLabel.Text -ne "x") {$UserRolesGrid_QueryLabel.Text = "Fetched $($AllRoles.RowCount) rows in $($time) - Query: `"$($SearchVal)`""} else {$UserRolesGrid_QueryLabel.Text = "Enter a value and/or press enter to search user. Duration time depends on search value"; check}
            }
        }
    })
    $UserRolesGrid.Controls.Add($SearchRoleTextBox)
    
    $UserRolesGridStatusLabel = New-Object System.Windows.Forms.Label
    $UserRolesGridStatusLabel.Location = New-Object System.Drawing.Size($($dgv.Right - ($($dgv.Width/2-20))),$SearchRoleTextBox.Location.Y)
    $UserRolesGridStatusLabel.Size = New-Object System.Drawing.Size($($dgv.Width/2-20),$SearchRoleTextBox.Height)
    $UserRolesGridStatusLabel.TextAlign = "MiddleCenter"
    $UserRolesGridStatusLabel.Add_Click({
            $removelist = $addlist = @()
        foreach($i in $CurrentRoles.Rows) {
            $exists = $false
            foreach($j in $BackupRoles.Rows) {
                if ($i.Cells['Group'].Value -eq $j.Cells['Group'].Value) {
                    $exists = $true
                    break
                }
            }
            if (!$exists) {
                $addlist += $i.Cells['Group'].Value
            }
        }
        foreach($i in $BackupRoles.Rows) {
            $exists = $false
            foreach($j in $CurrentRoles.Rows) {
                if ($i.Cells['Group'].Value -eq $j.Cells['Group'].Value) {
                    $exists = $true
                    break
                }
            }
            if (!$exists) {
                $removelist += $i.Cells['Group'].Value
            }
        }
        if ($removelist.Count -gt 0 -or $addlist.Count -gt 0) {
            $MessageBody = "Current overview:`n`nAdd ($($addlist.Count))" + $(if($addlist.Count -gt 0) {":`n$($addlist | Out-String)"} else {"`n"}) + "`nRemove ($($removelist.Count))" + $(if($removelist.Count -gt 0) {":`n$($removelist | Out-String)"})
            $MessageTitle = "Confirm choice"
            [Microsoft.VisualBasic.Interaction]::MsgBox($MessageBody,'OkOnly,SystemModal,Information',$MessageTitle)
        }
    })
    $UserRolesGrid.Controls.Add($UserRolesGridStatusLabel)

    $UserRolesGrid_QueryLabel = New-Object System.Windows.Forms.Label
    $UserRolesGrid_QueryLabel.Location = New-Object System.Drawing.Size($dgv.Location.X, $dgv.Bottom)
    $UserRolesGrid_QueryLabel.Size = New-Object System.Drawing.Size($dgv.Width, 20)
    $UserRolesGrid_QueryLabel.Text = "Enter a value and/or press enter to search role. Duration time depends on search value"
    $UserRolesGrid_QueryLabel.ForeColor = "Yellow"
    $UserRolesGrid_QueryLabel.BackColor = "Blue"
    $UserRolesGrid.Controls.Add($UserRolesGrid_QueryLabel)

    $CurrentRoles = New-Object System.Windows.Forms.DataGridView
    $AllRoles = New-Object System.Windows.Forms.DataGridView
    $BackupRoles = New-Object System.Windows.Forms.DataGridView
    $CurrentRoles.RowsDefaultCellStyle.BackColor = $AllRoles.RowsDefaultCellStyle.BackColor = "LightBlue"
    $CurrentRoles.DefaultCellStyle.SelectionBackColor = $AllRoles.DefaultCellStyle.SelectionBackColor = "Yellow"
    $CurrentRoles.DefaultCellStyle.SelectionForeColor = $AllRoles.DefaultCellStyle.SelectionForeColor = "Blue"
    $CurrentRoles.Location = New-Object System.Drawing.Size(0, $($SearchRoleTextBox.Bottom + 3))
    $CurrentRoles.Size = New-Object System.Drawing.Size($($dgv.Width/2-20),$($dgv.Height-40))
    $CurrentRoles.ColumnCount = 4

    $ShowCategory = New-Object System.Windows.Forms.Button
    $ShowCategory.Location = New-Object System.Drawing.Size($($CurrentRoles.Right+2), $($CurrentRoles.Location.Y-1))
    $ShowCategory.Size = New-Object System.Drawing.Size(36,24)
    $ShowCategory.Text = 1
    $ShowCategory.Add_Click({
        for ($i=1;$i-le $CurrentRoles.ColumnCount;$i++) {
            if ($i -gt 2) {$j = $i-1} else {$j = $i}
            if ($i -eq $ShowCategory.Text -or $ShowCategory.Text -eq 2) {
                if ($ShowCategory.Text -eq 2 -and $j -eq 1) {$CurrentRoles.Columns[0].Visible = $AllRoles.Columns[0].Visible = $false; $CurrentRoles.Columns[$j].Visible = $AllRoles.Columns[$j].Visible = $true} else {$CurrentRoles.Columns[$j].Visible = $AllRoles.Columns[$j].Visible = $true}
                $CurrentRoles.Columns[$j].Visible = $AllRoles.Columns[$j].Visible = $true
            } else {
                $CurrentRoles.Columns[0].Visible = $AllRoles.Columns[0].Visible = $true
                $CurrentRoles.Columns[$j].Visible = $AllRoles.Columns[$j].Visible = $false
            }
        }
        if ($ShowCategory.Text -eq 2) {for($i=2;$i -le 3; $i++) {$CurrentRoles.Columns[$i].Visible = $AllRoles.Columns[$i].Visible = $false}}
        if ($ShowCategory.Text -ne 5) {$ShowCategory.Text = [int]$ShowCategory.Text + 1} else {$ShowCategory.Text = 1}
    })
    $UserRolesGrid.Controls.Add($ShowCategory)

    $ReloadRoles = New-Object System.Windows.Forms.Button
    $ReloadRoles.Location = New-Object System.Drawing.Size($($CurrentRoles.Right+2), $ShowCategory.Bottom)
    $ReloadRoles.Size = New-Object System.Drawing.Size(36, 36)
    if (!(Test-Path variable:$ReloadImage)){
        $ReloadRoles.Image = $ReloadImage
    } else {
        $ReloadRoles.Text = "⟳"
    }
    $ReloadRoles.Add_Click({
        $SaveButton.Visible = $false
        $CurrentRoles.Rows.Clear()
        memberof
        check
        $SearchRoleTextBox.Focus()
    })
    $UserRolesGrid.Controls.Add($ReloadRoles)

    $RemoveRole = New-Object System.Windows.Forms.Button
    $RemoveRole.Location = New-Object System.Drawing.Size($($CurrentRoles.Right+2), $($ShowCategory.Bottom+(($UserRolesGrid.Height-$ShowCategory.Bottom+1)/2-70)))
    $RemoveRole.Size = New-Object System.Drawing.Size(36,70)
    $RemoveRole.Text = "✖"
    $RemoveRole.FlatStyle = "Flat"
    $RemoveRole.Add_Click({
        $count = $CurrentRoles.SelectedRows.Count
        $remove = $count
        for ($ia=$CurrentRoles.Rows.Count-1; $ia -ge 0; $ia--) {
            if ($CurrentRoles.Rows[$ia].Selected -and $count -gt 0) {
                $CurrentRoles.Rows.Remove($CurrentRoles.Rows[$ia])
                $count--
            }
            if ($count -eq 0) {break}
        }
        $UserRolesGridStatusLabel.BackColor = "Lightgreen"
        if ($remove -eq 1) {$UserRolesGridStatusLabel.Text = "Removed $($remove) item"} else {$UserRolesGridStatusLabel.Text = "Removed $($remove) items"}
        check
    })
    $UserRolesGrid.Controls.Add($RemoveRole)

    $AddRole = New-Object System.Windows.Forms.Button
    $AddRole.Location = New-Object System.Drawing.Size($($CurrentRoles.Right+2), $RemoveRole.Bottom)
    $AddRole.Size = New-Object System.Drawing.Size(36,70)
    if (!(Test-Path variable:$AddImage)){
        $AddRole.Image = $AddImage
    } else {
        $AddRole.Text = "+"
    }
    $AddRole.FlatStyle = "Flat"
    $AddRole.Add_Click({
        $add = 0
        foreach ($i in $AllRoles.SelectedRows) {
            $in = $false
            foreach ($j in $CurrentRoles.Rows) {
                if ($j.Cells['Group'].Value -eq $i.Cells['Group'].Value) {
                    $in = $true
                    break
                }
            }
            if (!$in) {
                $CurrentRoles.Rows.Add($i.Cells['Group'].Value, $i.Cells['Description'].Value, $i.Cells['Category'].Value, $i.Cells['ManagedBy'].Value)
                $exists = $false
                foreach($k in $BackupRoles.Rows) {
                    if ($i.Cells['Group'].Value -eq $k.Cells['Group'].Value){
                        $exists = $true
                    }
                }
                if (!$exists) {
                    $add++
                    $CurrentRoles.Rows[$CurrentRoles.RowCount -1].DefaultCellStyle.BackColor = "Lightgreen"
                    $CurrentRoles.Rows[$CurrentRoles.RowCount -1].DefaultCellStyle.SelectionBackColor = "Orange"
                }
            }
        }
        if ($add -gt 0) {
            if ($add -eq 1) {$UserRolesGridStatusLabel.Text = "Added $($add) item"} else {$UserRolesGridStatusLabel.Text = "Added $($add) items"}
            if (($AllRoles.SelectedRows.Count - $add) -gt 0) {
                $UserRolesGridStatusLabel.BackColor = "Orange"
                if (($AllRoles.SelectedRows.Count - $add) -eq 1) {$UserRolesGridStatusLabel.Text += "; 1 item was already in the list"} else {$UserRolesGridStatusLabel.Text += "; $($AllRoles.SelectedRows.Count - $add) items were already in the list"}
            } else {
                $UserRolesGridStatusLabel.BackColor = "Lightgreen"
            }
        } else {
            $UserRolesGridStatusLabel.BackColor = "Orange"
            if ($AllRoles.SelectedRows.Count -eq 1) {$UserRolesGridStatusLabel.Text = "The item is already in the list"} else {$UserRolesGridStatusLabel.Text = "The items are already in the list"}
        }
        check
    })
    $UserRolesGrid.Controls.Add($AddRole)

    $RemoveRole.Font = $AddRole.Font = New-Object System.Drawing.Font("Calibri",18,[System.Drawing.FontStyle]::Regular)
    $RemoveRole.Enabled = $AddRole.Enabled = $false

    $AllRoles.Location = New-Object System.Drawing.Size($($RemoveRole.Right+2),$($CurrentRoles.Location.Y))
    $AllRoles.Size = New-Object System.Drawing.Size($CurrentRoles.Size)
    $AllRoles.ColumnCount = $BackupRoles.ColumnCount = 4
    
    $CurrentRoles.Columns[0].Name = $AllRoles.Columns[0].Name = $BackupRoles.Columns[0].Name = "Group"
    $CurrentRoles.Columns[1].Name = $AllRoles.Columns[1].Name = $BackupRoles.Columns[1].Name = "Description"
    $CurrentRoles.Columns[2].Name = $AllRoles.Columns[2].Name = $BackupRoles.Columns[2].Name = "Category"
    $CurrentRoles.Columns[3].Name = $AllRoles.Columns[3].Name = $BackupRoles.Columns[3].Name = "ManagedBy"
    for ($i=1;$i -le 3; $i++){$CurrentRoles.Columns[$i].Visible = $AllRoles.Columns[$i].Visible = $false}
    $CurrentRoles.AllowUserToResizeRows = $AllRoles.AllowUserToResizeRows = $CurrentRoles.AllowUserToResizeColumns = $AllRoles.AllowUserToResizeColumns = $CurrentRoles.AllowUserToAddRows = $AllRoles.AllowUserToAddRows = $BackupRoles.AllowUserToAddRows = $false
    $CurrentRoles.ColumnHeadersHeightSizeMode = $AllRoles.ColumnHeadersHeightSizeMode = 1
    $CurrentRoles.EnableHeadersVisualStyles = $AllRoles.EnableHeadersVisualStyles = 0
    $CurrentRoles.RowHeadersVisible = $AllRoles.RowHeadersVisible = $false
    $CurrentRoles.ReadOnly = $AllRoles.ReadOnly = $true
    $CurrentRoles.ColumnHeadersDefaultCellStyle.Font = $AllRoles.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Calibri",11,[System.Drawing.FontStyle]::Bold)
    $CurrentRoles.DefaultCellStyle.Font = $AllRoles.DefaultCellStyle.Font = New-Object System.Drawing.Font("Calibri",10,[System.Drawing.FontStyle]::Regular)
    $CurrentRoles.BorderStyle = $AllRoles.BorderStyle = "None"
    $CurrentRoles.SelectionMode = $AllRoles.SelectionMode = 1
    $CurrentRoles.MultiSelect = $AllRoles.MultiSelect = $true
    $UserRolesGrid.Controls.Add($CurrentRoles)
    $UserRolesGrid.Controls.Add($AllRoles)

    $CurrentRoles.Columns[0..1] | Foreach-Object{
        $_.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
    }
    $AllRoles.Columns[0..1] | Foreach-Object{
        $_.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
    }
    
    $CurrentRoles.Add_RowStateChanged({
        $RemoveRole.Enabled = $CurrentRoles.SelectedRows.Count -gt 0
        if ($CurrentRoles.RowCount -gt 0) {
            $RemoveRole.BackColor = "Red"
        } else {
            $RemoveRole.BackColor = "Transparent"
        }
    })
    
    $AllRoles.Add_RowStateChanged({
        $AddRole.Enabled = $AllRoles.SelectedRows.Count -gt 0
        $AddRole.BackColor = "Lightgreen"
        if ($AllRoles.RowCount -gt 0) {
            $AddRole.BackColor = "Lightgreen"
        } else {
            $AddRole.BackColor = "Transparent"
        }
    })
    
    $AllGroups = New-Object System.Windows.Forms.DataGridView
    $AllMembers = New-Object System.Windows.Forms.DataGridView
    $NewMembers = New-Object System.Windows.Forms.DataGridView
    $BackupGroups = New-Object System.Windows.Forms.DataGridView

    $gridviews = @($AllGroups, $AllMembers, $NewMembers, $BackupGroups)
    $AllGroups.Location = New-Object System.Drawing.Size(0, $($dgv.Top))
    
    foreach($i in $gridviews) {
        $i.DefaultCellStyle.SelectionBackColor = "Yellow"
        $i.DefaultCellStyle.SelectionForeColor = "Blue"
        if ($i -ne $AllGroups -and $i -ne $BackupGroups) {
            $i.ColumnCount = 2;
            if ($i -eq $AllMembers) {
                $i.Columns[0].Name = "Current member";
                $i.Location = New-Object System.Drawing.Size($CurrentRoles.Location)
            } else {
                $i.Columns[0].Name = "Possible member";
                $i.Location = New-Object System.Drawing.Size($AllRoles.Location)
            }
            $i.Size = New-Object System.Drawing.Size($CurrentRoles.Width,$CurrentRoles.Height)
            $i.Columns[1].Name = "Username"
        } else {
            $i.Size = New-Object System.Drawing.Size($dgv.Size)
            $i.ColumnCount = 4
            $i.Columns[0].Name = "Group"
            $i.Columns[1].Name = "Description"
            $i.Columns[2].Name = "Category"
            $i.Columns[3].Name = "ManagedBy"
        }
        $i.AllowUserToResizeRows = $i.AllowUserToResizeColumns = $i.AllowUserToAddRows = $false
        $i.ColumnHeadersHeightSizeMode = 1
        $i.EnableHeadersVisualStyles = 0
        $i.RowHeadersVisible = $false
        $i.ReadOnly = $true
        $i.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Calibri",11,[System.Drawing.FontStyle]::Bold)
        $i.DefaultCellStyle.Font = New-Object System.Drawing.Font("Calibri",10,[System.Drawing.FontStyle]::Regular)
        $i.BorderStyle = "None"
        $i.SelectionMode = 1
        if ($i -ne $AllGroups) {$i.MultiSelect = $true} else {$i.MultiSelect = $false}
        $GroupGrid.Controls.Add($i)
        $i.Columns[0..1] | Foreach-Object{
            $_.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
        }
        $j++
    }
    $BackupGroups.Visible = $false
    
    $AllGroups.Add_RowStateChanged({
        if ($BlockLabel.Text.Length -eq 0) {
        if ($AllGroups.SelectedRows.Count -gt 0) {
            $GroupsTextbox.Text = $AllGroups.SelectedRows[0].Cells['Group'].Value
        } else {
            $GroupsTextbox.Text = ""
        }}
    })

    $TopPanel = New-Object System.Windows.Forms.Panel
    $TopPanel.Location = New-Object System.Drawing.Size($($dgv.Right + 2),0)
    $TopPanel.Width = 180
    $TopPanel.Height = 58
    $TopPanel.Dock = "Top"
    $form.Controls.Add($TopPanel)
        
    $SearchLabel = New-Object System.Windows.Forms.Label
    $SearchLabel.Location = New-Object System.Drawing.Size(4,$($TopPanel.Bottom - 24))
    $SearchLabel.Size = New-Object System.Drawing.Size(50,24)
    $SearchLabel.Text = "Search"
    $SearchLabel.TextAlign = "MiddleLeft"
    $SearchLabel.BackColor = "Transparent"
    $TopPanel.Controls.Add($SearchLabel)

    $SearchUserTextBox = New-Object System.Windows.Forms.TextBox
    $SearchUserTextBox.Location = New-Object System.Drawing.Size($SearchLabel.Right,$($SearchLabel.Location.Y-2))
    $SearchUserTextBox.Size = New-Object System.Drawing.Size($UsernameTextbox.Size)
    $SearchUserTextBox.Text = ""
    $SearchUserTextBox.SendToBack()
    $SearchUserTextBox.MaxLength = 25
    $SearchUserTextBox.BackColor = "Yellow"
    $SearchUserTextBox.ForeColor = "Blue"
    $SearchUserTextBox.TextAlign = "center"
    $SearchUserTextBox.AllowDrop = $true
    $SearchUserTextBox.Add_TextChanged({
        $ClearSearch.Visible = $SearchUserTextBox.Text.Length -gt 0
        $BlockLabel.Text = "x"
        $s = ""
        forEach ($i in $dgv.Rows){
            if ("$($i.Cells['Display name'].Value)".ToLower().Contains($SearchUserTextBox.Text) -or
                "$($i.Cells['Username'].Value)".ToLower().Contains($SearchUserTextBox.Text) -or
                "$($i.Cells['Name'].Value)".ToLower().Contains($SearchUserTextBox.Text) -or
                $SearchUserTextBox.Text -eq ""){
                $dgv.FirstDisplayedScrollingRowIndex = $i.Index
                $dgv.Refresh()
                $dgv.CurrentCell = $i.Cells['UserName']
                $i.Selected = $true
                $BlockLabel.Text = ""
                $UsernameTextbox.Text = $i.Cells['Username'].Value
                $s = "v"
                break
            }
        }
        if ($s -ne "v") {
            if ($dgv.RowCount -ne 0) {
                $dgv.ClearSelection()
                $UsernameTextbox.Text = $InfoButton.Text = $RoleButton.Text = ""
                if (!(Test-Path variable:$UserinfoImage)){
                    $InfoButton.Image = $UserinfoImage
                } else {
                    $InfoButton.Text = " I"
                }
                if (!(Test-Path variable:$userrolesImage)){
                        $RoleButton.Image = $userrolesImage
                } else {
                        $RoleButton.Text = "R"
                }
                $UserPropertiesGrid.Visible = $InfoButton.Visible = $RoleButton.Visible = $UserRolesGrid.Visible = $false; $UserGrid.Visible = $true
            }
        }
        $BlockLabel.Text = ""
    })
    $SearchUserTextBox.Add_KeyDown({
        if ($_.KeyCode -eq "Enter"){
            if ($SearchUserTextBox.Text.Length -lt 3 -and !$UserTypeCheckBox.Checked) {
                $MessageBody = "This query could take more than 2 minutes!`n`nContinue?"
                $MessageTitle = "Confirm choice"
                $Result = [Microsoft.VisualBasic.Interaction]::MsgBox($MessageBody,'OkCancel,DefaultButton2,SystemModal,Critical',$MessageTitle)
                if ($Result -eq "Cancel") {return}
            }
            $BlockLabel.Text = "y"
            refresh
            $SearchUserTextBox.SelectionStart = 0
            $SearchUserTextBox.SelectionLength = $SearchUserTextBox.Text.Length
        }
        $BlockLabel.Text = ""
    })
    $TopPanel.Controls.Add($SearchUserTextBox)

    $SearchGroupTextBox = New-Object System.Windows.Forms.TextBox
    $SearchGroupTextBox.Location = New-Object System.Drawing.Size($SearchLabel.Right,$($SearchLabel.Location.Y-2))
    $SearchGroupTextBox.Size = New-Object System.Drawing.Size($GroupsTextbox.Size)
    $SearchGroupTextBox.Text = ""
    $SearchGroupTextBox.Visible = $false
    $SearchGroupTextBox.SendToBack()
    $SearchGroupTextBox.MaxLength = 25
    $SearchGroupTextBox.BackColor = "Yellow"
    $SearchGroupTextBox.ForeColor = "Blue"
    $SearchGroupTextBox.TextAlign = "center"
    $SearchGroupTextBox.AllowDrop = $true
    $SearchGroupTextBox.Add_TextChanged({
        $ClearSearchGroupTextBox.Visible = $SearchGroupTextBox.Text.Length -gt 0
        $BlockLabel.Text = "x"
        $s = ""
        forEach ($i in $dgv.Rows){
            if ("$($i.Cells['Group'].Value)".ToLower().Contains($SearchGroupTextBox.Text) -or
                "$($i.Cells['Description'].Value)".ToLower().Contains($SearchGroupTextBox.Text) -or
                "$($i.Cells['ManagedBy'].Value)".ToLower().Contains($SearchGroupTextBox.Text) -or
                $SearchGroupTextBox.Text -eq ""){
                $AllGroups.FirstDisplayedScrollingRowIndex = $i.Index
                $AllGroups.Refresh()
                $AllGroups.CurrentCell = $i.Cells['Group']
                $i.Selected = $true
                $GroupsTextbox.Text = $i.Cells['Group'].Value
                $s = "v"
                break
            }
        } if ($s -ne "v") {if ($dgv.RowCount -ne 0) {$AllGroups.ClearSelection(); $GroupsTextbox.Text = ""}}
        $BlockLabel.Text = ""
    })
    $SearchGroupTextBox.Add_KeyDown({
        if ($_.KeyCode -eq "Enter"){
            if ($SearchGroupTextBox.Text.Length -lt 3) {
                $MessageBody = "This query could take more than 2 minutes!`n`nContinue?"
                $MessageTitle = "Confirm choice"
                $Result = [Microsoft.VisualBasic.Interaction]::MsgBox($MessageBody,'OkCancel,DefaultButton2,SystemModal,Critical',$MessageTitle)
                if ($Result -eq "Cancel") {return}
            }
            $BlockLabel.Text = "y"
            refresh_group
            $BlockLabel.Text = ""
        }
    })
    $TopPanel.Controls.Add($SearchGroupTextBox)

    $SearchGroupEnter= New-Object System.Windows.Forms.Label
    $SearchGroupEnter.Location = New-Object System.Drawing.Size($($SearchGroupTextBox.Width - $SearchUserTextBox.Height))#$SearchUserTextBox.Right, $SearchUserTextBox.Location.Y)
    $SearchGroupEnter.Size = New-Object System.Drawing.Size($SearchUserTextBox.Height, $SearchUserTextBox.Height)
    $SearchGroupEnter.Font = New-Object System.Drawing.Font("Calibri Light",13,[System.Drawing.FontStyle]::Bold)
    #$SearchGroupEnter.Text = "⌕"
    $SearchGroupEnter.Image = $searchImage
    $SearchGroupEnter.Cursor = "Hand"
    $SearchGroupEnter.FlatStyle = "Flat"
    $SearchGroupEnter.BackColor = "Transparent"
    $SearchGroupEnter.Visible = $true
    $SearchGroupEnter.Add_Click({
        if ($SearchGroupTextBox.Text.Length -lt 3) {
            $MessageBody = "This query could take more than 2 minutes!`n`nContinue?"
            $MessageTitle = "Confirm choice"
            $Result = [Microsoft.VisualBasic.Interaction]::MsgBox($MessageBody,'OkCancel,DefaultButton2,SystemModal,Critical',$MessageTitle)
            if ($Result -eq "Cancel") {
                $SearchGroupTextBox.Focus()
                return
            }
        }
        $BlockLabel.Text = "y"
        refresh_group
        $SearchGroupTextBox.Focus()
        $BlockLabel.Text = ""
    })
    $SearchGroupTextBox.Controls.Add($SearchGroupEnter)

    if($SearchGroupTextBox.CanFocus){
       $SearchGroupTextBox.Focus()
    }else{
       $SearchGroupTextBox.Select()
    }
    
    $SearchEnterButton = New-Object System.Windows.Forms.Label
    $SearchEnterButton.Location = New-Object System.Drawing.Size($($SearchUserTextBox.Width - $SearchUserTextBox.Height))
    $SearchEnterButton.Size = New-Object System.Drawing.Size($SearchUserTextBox.Height, $SearchUserTextBox.Height)
    $SearchEnterButton.Font = New-Object System.Drawing.Font("Calibri Light",13,[System.Drawing.FontStyle]::Bold)
    if (!(Test-Path variable:$SearchImage)){
        $SearchEnterButton.Image = $SearchImage
    } else {
        $SearchEnterButton.Text = "⌕"
    }
    $SearchEnterButton.Cursor = "Hand"
    $SearchEnterButton.FlatStyle = "Flat"
    $SearchEnterButton.BackColor = "Transparent"
    $SearchEnterButton.Visible = $true
    $SearchEnterButton.Add_Click({
        if ($SearchUserTextBox.Text.Length -lt 3 -and !$UserTypeCheckBox.Checked) {
            $MessageBody = "This query could take more than 2 minutes!`n`nContinue?"
            $MessageTitle = "Confirm choice"
            $Result = [Microsoft.VisualBasic.Interaction]::MsgBox($MessageBody,'OkCancel,DefaultButton2,SystemModal,Critical',$MessageTitle)
            if ($Result -eq "Cancel") {
                if ($SearchUserTextBox.Visible) {
                    $SearchUserTextBox.Focus()
                } elseif ($SearchGroupTextBox.Visible) {
                    $SearchGroupTextBox.Focus()
                }
                return
            }
        }
        $BlockLabel.Text = "y"
        refresh
        $SearchUserTextBox.Focus()
        $BlockLabel.Text = ""
    })
    $SearchUserTextBox.Controls.Add($SearchEnterButton)

    if($SearchUserTextBox.CanFocus){
       $SearchUserTextBox.Focus()
    }else{
       $SearchUserTextBox.Select()
    }
    
    $UserTypeCheckBox = New-Object System.Windows.Forms.CheckBox
    $UserTypeCheckBox.Location = New-Object System.Drawing.Size($SearchUserTextBox.Location.X,$($SearchUserTextBox.Top-$SearchUserTextBox.Height-4))
    $UserTypeCheckBox.Size = New-Object System.Drawing.Size($SearchUserTextBox.Size)
    $UserTypeCheckBox.BackColor = "Transparent"
    if ($adm.Length -gt 3) {
        $pre = $adm.Substring(4, $($adm.Length-4))
        if($adm.Substring(0, 4) -eq "[#l]") {$pre = "$($pre)*"}
        if($adm.Substring(0, 4) -eq "[#c]") {$pre = "*$($pre)*"}
        if($adm.Substring(0, 4) -eq "[#r]") {$pre = "*$($pre)"}
        $UserTypeCheckBox.Text = $pre
    } else {
        $UserTypeCheckBox.Text = "!"; $UserTypeCheckBox.BackColor = "Orange"
    }
    $UserTypeCheckBox.Checked = $false
    $UserTypeCheckBox.Add_CheckStateChanged({
        $AdminUpdate.BackColor = "Transparent"
        $SetAdminPrefixSuffixGroup.Visible = $($UserTypeCheckBox.Checked -and $UserTypeCheckBox.Text -eq "!")
        $SearchUserTextBox.Visible = !$($UserTypeCheckBox.Checked -and $UserTypeCheckBox.Text -eq "!")
        $UserGrid_QueryLabel.Visible = !$($UserTypeCheckBox.Checked -and $UserTypeCheckBox.Text -eq "!")
        if (($($UserTypeCheckBox.Text -ne "!" -and $UserTypeCheckBox.Checked) -or !$UserTypeCheckBox.Checked)) {if (!$UserTypeCheckBox.Checked -and $SearchUserTextBox.Text.Length -eq 0) {$BlockLabel.Text = "x"};refresh; $BlockLabel.Text = ""; $SearchUserTextBox.Focus()}
        if ($UserTypeCheckBox.Checked -and $UserTypeCheckBox.Text -eq "!") {$UserTypeCheckBox.Visible = $false; $AdminTextBox.Focus();  $AdminUpdate.BackColor = "Yellow"}
    })
    $TopPanel.Controls.Add($UserTypeCheckBox)
    
    $ClearSearch = New-Object System.Windows.Forms.Label
    $ClearSearch.Location = New-Object System.Drawing.Size(0,2)
    $ClearSearch.Size = New-Object System.Drawing.Size(15,19)
    $ClearSearch.Text = "✘"
    $ClearSearch.Visible = $false
    $ClearSearch.BackColor = "Transparent"
    $ClearSearch.ForeColor = "Red"
    $ClearSearch.Cursor = "Hand"
    $ClearSearch.BringToFront()
    $ClearSearch.Add_Click({
        $SearchUserTextBox.Clear()
    })
    $SearchUserTextBox.Controls.Add($ClearSearch)
    
    $ClearSearchGroupTextBox = New-Object System.Windows.Forms.Label
    $ClearSearchGroupTextBox.Location = New-Object System.Drawing.Size(0,2)
    $ClearSearchGroupTextBox.Size = New-Object System.Drawing.Size(15,19)
    $ClearSearchGroupTextBox.Text = "✘"
    $ClearSearchGroupTextBox.Visible = $false
    $ClearSearchGroupTextBox.BackColor = "Transparent"
    $ClearSearchGroupTextBox.ForeColor = "Red"
    $ClearSearchGroupTextBox.Cursor = "Hand"
    $ClearSearchGroupTextBox.BringToFront()
    $ClearSearchGroupTextBox.Add_Click({
        $SearchGroupTextBox.Clear()
    })
    $SearchGroupTextBox.Controls.Add($ClearSearchGroupTextBox)  

    $SetAdminPrefixSuffixGroup = New-Object System.Windows.Forms.GroupBox
    $SetAdminPrefixSuffixGroup.Location = New-Object System.Drawing.Size($UsernameTextbox.Location.X, 4)
    $SetAdminPrefixSuffixGroup.Size = New-Object System.Drawing.Size($SearchUserTextBox.Width, $($TopPanel.Height))
    $SetAdminPrefixSuffixGroup.Visible = $false
    $SetAdminPrefixSuffixGroup.BringToFront()
    $TopPanel.Controls.Add($SetAdminPrefixSuffixGroup)

    $AdminTextBox = New-Object System.Windows.Forms.TextBox
    $AdminTextBox.Location = New-Object System.Drawing.Size(0,0)
    $AdminTextBox.Size = New-Object System.Drawing.Size($SearchUserTextBox.Width, $SearchUserTextBox.Height)
    if ($adm.Length -gt 3) {
        $AdminTextBox.Text = $adm.Substring(4, $($adm.Length-4));
    } else {
        $AdminTextBox.Text = ""
    }
    $AdminTextBox.MaxLength = 25
    $AdminTextBox.BackColor = "Orange"
    $AdminTextBox.ForeColor = "Blue"
    $AdminTextBox.TextAlign = "center"
    $AdminTextBox.AllowDrop = $true
    $AdminTextBox.Add_TextChanged({
        $AdminUpdateSave.Visible = $AdminTextBox.Text.Length -gt 0
        $AdminUpdateClear.Visible = $AdminTextBox.Text.Length -gt 0
        $ToolTip.SetToolTip($LeftRadioButton, "Prefix: '$($AdminTextBox.Text)Username'")
        $ToolTip.SetToolTip($RightRadioButton, "Suffix: 'Username$($AdminTextBox.Text)'")
    })
    $AdminTextBox.Add_KeyDown({
        if ($_.KeyCode -eq "Enter" -and $AdminTextBox.Text.Length -gt 0){
            set-admin-prefix
            $AdminUpdateSave.Visible = $false
        }
    })
    $SetAdminPrefixSuffixGroup.Controls.Add($AdminTextBox)

    $LeftRadioButton = New-Object System.Windows.Forms.RadioButton
    $LeftRadioButton.Location = New-Object System.Drawing.Size(0, $($AdminTextBox.Bottom))
    $LeftRadioButton.Size = New-Object System.Drawing.Size($($AdminTextBox.Width/3),30)
    $LeftRadioButton.Text = "Prefix"
    if ($adm.Length -gt 3) {
        if ($adm.Substring(0, 4) -eq "[#l]") {
            $LeftRadioButton.Checked = $true
        }
    } else {
        $LeftRadioButton.Checked = $true
    }
    $SetAdminPrefixSuffixGroup.Controls.Add($LeftRadioButton)
    $LeftRadioButton.Add_Click({
        set-admin-prefix
    })

    $CenterRadioButton = New-Object System.Windows.Forms.RadioButton
    $CenterRadioButton.Location = New-Object System.Drawing.Size($(($AdminTextBox.Width/2)-30), $($AdminTextBox.Bottom))
    $CenterRadioButton.Size = New-Object System.Drawing.Size($($AdminTextBox.Width/3),30)
    $CenterRadioButton.Text = "Around"
    if ($adm.Length -gt 3) {
        if ($adm.Substring(0, 4) -eq "[$]") {
            $CenterRadioButton.Checked = $true
        }
    }
    $SetAdminPrefixSuffixGroup.Controls.Add($CenterRadioButton)
    $CenterRadioButton.Add_Click({
        set-admin-prefix
    })

    $RightRadioButton = New-Object System.Windows.Forms.RadioButton
    $RightRadioButton.Location = New-Object System.Drawing.Size($($AdminTextBox.Width-$AdminTextBox.Width/3), $($AdminTextBox.Bottom))
    $RightRadioButton.Size = New-Object System.Drawing.Size($($AdminTextBox.Width/3),30)
    $RightRadioButton.Text = "Suffix"
    $RightRadioButton.RightToLeft = "Yes"
    if ($adm.Length -gt 3) {
        if ($adm.Substring(0, 4) -eq "[#r]") {
            $RightRadioButton.Checked = $true
        }
    }
    $SetAdminPrefixSuffixGroup.Controls.Add($RightRadioButton)
    $RightRadioButton.Add_Click({
        set-admin-prefix
    })
    
    $AdminLabel = New-Object System.Windows.Forms.Label
    $AdminLabel.Location = New-Object System.Drawing.Size(0, $($LeftRadioButton.Bottom+2))
    $AdminLabel.Size = New-Object System.Drawing.Size($SetAdminPrefixSuffixGroup.Width, 35)
    $AdminLabel.Visible = $true
    $AdminLabel.TextAlign = "MiddleCenter"
    $AdminLabel.Text = "Enter the admin specific prefix/suffix"
    $SetAdminPrefixSuffixGroup.Controls.Add($AdminLabel)

    $BlockLabel = New-Object System.Windows.Forms.Label
    $BlockLabel.Visible = $false
    $TopPanel.Controls.Add($BlockLabel)

    $SaveButton = New-Object System.Windows.Forms.Button
    $SaveButton.Location = New-Object System.Drawing.Size($($dgv.Right - (268)),$UsernameTextbox.Location.Y)
    $SaveButton.Size = New-Object System.Drawing.Size(268,$SearchUserTextBox.Height)
    $SaveButton.Font = New-Object System.Drawing.Font("Calibri",11,[System.Drawing.FontStyle]::Bold)
    $SaveButton.Visible = $false
    $SaveButton.FlatStyle = "Flat"
    $SaveButton.Text = ""
    $SaveButton.Add_Click({
        save
    })
    $BottomPanel.Controls.Add($SaveButton)
    
    $StatusLabel = New-Object System.Windows.Forms.Button
    $StatusLabel.Location = New-Object System.Drawing.Size($SaveButton.Location)
    $StatusLabel.Size = New-Object System.Drawing.Size($SaveButton.Size)
    $StatusLabel.Visible = $false
    $StatusLabel.BackColor = "Transparent"
    $StatusLabel.TextAlign = "MiddleCenter"
    $StatusLabel.FlatAppearance.BorderColor = "Black"
    $StatusLabel.FlatStyle = "Flat"
    $StatusLabel.Add_Click({
        if ($StatusLabel.Text.Length -gt 0) {
            $MessageBody = $StatusLabelTotal.Text
            $MessageTitle = "Status report"
            $Result = [Microsoft.VisualBasic.Interaction]::MsgBox($MessageBody,'SystemModal,Information',$MessageTitle)
        }
    })
    $BottomPanel.Controls.Add($StatusLabel)
    
    $StatusLabelTotal = New-Object System.Windows.Forms.Label
    
    $RestoreRadioButton = New-Object System.Windows.Forms.RadioButton
    $RestoreRadioButton.Location = New-Object System.Drawing.Size($AllRoles.Location.X,$($SearchUserTextBox.Top-30))
    $RestoreRadioButton.Size = New-Object System.Drawing.Size(70,30)
    $RestoreRadioButton.Text = "Restore"
    $RestoreRadioButton.Visible = $false
    $RestoreRadioButton.Checked = $false
    $TopPanel.Controls.Add($RestoreRadioButton)
    $RestoreRadioButton.Add_Click({
        $OldPasswordTextBox.Visible = $RestoreRadioButton.Checked
        check
        $OldPasswordTextBox.Focus()
    })

    $ResetRadioButton = New-Object System.Windows.Forms.RadioButton
    $ResetRadioButton.Location = New-Object System.Drawing.Size($RestoreRadioButton.Location.X, $($SearchUserTextBox.Location.Y-1))
    $ResetRadioButton.Size = New-Object System.Drawing.Size($RestoreRadioButton.Size)
    $ResetRadioButton.Text = "Reset"
    $ResetRadioButton.Visible = $false
    $ResetRadioButton.Checked = $true
    $TopPanel.Controls.Add($ResetRadioButton)

    $ResetRadioButton.Add_Click({
        $OldPasswordTextBox.Visible = !$ResetRadioButton.Checked
        check
        $NewPasswordTextBox.Focus()
    })
    
    $EnableCheckBox = New-Object System.Windows.Forms.CheckBox
    $EnableCheckBox.Location = New-Object System.Drawing.Size($RestoreRadioButton.Location.X, $UsernameTextbox.Location.Y)
    $EnableCheckBox.Size = New-Object System.Drawing.Size($RestoreRadioButton.Size)
    $EnableCheckBox.Text = ""
    $EnableCheckBox.Visible = $false
    $EnableCheckBox.Checked = $false
    $BottomPanel.Controls.Add($EnableCheckBox)

    $EnableCheckBox.Add_Click({
        if ($EnableCheckBox.Text -ne ""){
            check
        }
    })

    $NewPasswordTextBox = New-Object System.Windows.Forms.TextBox
    $NewPasswordTextBox.Location = New-Object System.Drawing.Size($SaveButton.Location.X, $SearchUserTextBox.Location.Y)
    $NewPasswordTextBox.Size = New-Object System.Drawing.Size($SaveButton.Size)
    $NewPasswordTextBox.Text = ""
    $NewPasswordTextBox.Visible = $false
    $NewPasswordTextBox.BackColor = "Orange"
    $NewPasswordTextBox.UseSystemPasswordChar = $true
    $NewPasswordTextBox.AllowDrop = $true
    $NewPasswordTextBox.Add_TextChanged({
        #$NewPasswordTextBox.UseSystemPasswordChar = $true
        if ($NewPasswordTextBox.Text.Length -gt 0) {
            $NewPasswordTextBox.BackColor = "Lightgreen"
            $ShowHideNewPassLabel.Visible = $true
            $NewPassLabel.Visible = $false
        } else {
            $NewPasswordTextBox.BackColor = "Orange"
            $ShowHideNewPassLabel.Visible = $false
            $NewPassLabel.Visible = $true
        }
        check
    })
    $NewPasswordTextBox.Add_LostFocus({
        if ($NewPasswordTextBox.Text.Length -eq 0) {
            $NewPassLabel.Visible = $true
        }
    })
    $TopPanel.Controls.Add($NewPasswordTextBox)

    $ShowHideNewPassLabel = New-Object System.Windows.Forms.Label
    $ShowHideNewPassLabel.Location = New-Object System.Drawing.Size($($NewPasswordTextBox.Width - 20),1)
    $ShowHideNewPassLabel.Size = New-Object System.Drawing.Size(18,20)
    $ShowHideNewPassLabel.Text = "○"
    $ShowHideNewPassLabel.Cursor = "Hand"
    $ShowHideNewPassLabel.Visible = $false
    $ShowHideNewPassLabel.BackColor = "Transparent"
    $NewPasswordTextBox.Controls.Add($ShowHideNewPassLabel)
    $ShowHideNewPassLabel.Add_Click({
        if ($NewPasswordTextBox.UseSystemPasswordChar -eq $true) {
            $ShowHideNewPassLabel.Text = "●"
            $NewPasswordTextBox.UseSystemPasswordChar = $false
        } else {
            $ShowHideNewPassLabel.Text = "○"
            $NewPasswordTextBox.UseSystemPasswordChar = $true
        }
    })

    $NewPassLabel = New-Object System.Windows.Forms.Label
    $NewPassLabel.Location = New-Object System.Drawing.Size($($NewPasswordTextBox.Width/2-67.5),-1)
    $NewPassLabel.Size = New-Object System.Drawing.Size(135,25)
    $NewPassLabel.Text = "Enter new password"
    $NewPassLabel.TextAlign = "MiddleCenter"
    $NewPassLabel.BackColor = "Transparent"
    $NewPassLabel.ForeColor = "Black"
    $NewPassLabel.Add_Click({
        $NewPassLabel.Visible = $false
        $NewPasswordTextBox.Focus()
    })
    $NewPasswordTextBox.Controls.Add($NewPassLabel)

    $OldPasswordTextBox = New-Object System.Windows.Forms.TextBox
    $OldPasswordTextBox.Location = New-Object System.Drawing.Size($($NewPasswordTextBox.Location.X),4)
    $OldPasswordTextBox.Size = New-Object System.Drawing.Size($NewPasswordTextBox.Size)
    $OldPasswordTextBox.Text = ""
    $OldPasswordTextBox.Visible = $false
    $OldPasswordTextBox.BackColor = "Orange"
    $OldPasswordTextBox.UseSystemPasswordChar = $true
    $OldPasswordTextBox.AllowDrop = $true
    $OldPasswordTextBox.Add_TextChanged({
        #$OldPasswordTextBox.UseSystemPasswordChar = $true
        if ($OldPasswordTextBox.Text.Length -gt 0) {
            $OldPasswordTextBox.BackColor = "Lightgreen"
            $ShowHideOldPassLabel.Visible = $true
            $OldPassLabel.Visible = $false
        } else {
            $OldPasswordTextBox.BackColor = "Orange"
            $ShowHideOldPassLabel.Visible = $false
            $OldPassLabel.Visible = $true
        }
        check
    })
    $OldPasswordTextBox.Add_LostFocus({
        if ($OldPasswordTextBox.Text.Length -eq 0) {
            $OldPassLabel.Visible = $true
        }
    })
    $TopPanel.Controls.Add($OldPasswordTextBox)
    
    $ShowHideOldPassLabel = New-Object System.Windows.Forms.Label
    $ShowHideOldPassLabel.Location = New-Object System.Drawing.Size($($OldPasswordTextBox.Width - 20),1)
    $ShowHideOldPassLabel.Size = New-Object System.Drawing.Size(18,20)
    $ShowHideOldPassLabel.Text = "○"
    $ShowHideOldPassLabel.Cursor = "Hand"
    $ShowHideOldPassLabel.Visible = $false
    $ShowHideOldPassLabel.BackColor = "Transparent"
    $OldPasswordTextBox.Controls.Add($ShowHideOldPassLabel)
    $ShowHideOldPassLabel.Add_Click({
        if ($OldPasswordTextBox.UseSystemPasswordChar -eq $true) {
            $ShowHideOldPassLabel.Text = "●"
            $OldPasswordTextBox.UseSystemPasswordChar = $false
        } else {
            $ShowHideOldPassLabel.Text = "○"
            $OldPasswordTextBox.UseSystemPasswordChar = $true
        }
    })
    
    $OldPassLabel = New-Object System.Windows.Forms.Label
    $OldPassLabel.Location = New-Object System.Drawing.Size($($OldPasswordTextBox.Width/2-67.5),-1)
    $OldPassLabel.Size = New-Object System.Drawing.Size(135,25)
    $OldPassLabel.Text = "Enter old password"
    $OldPassLabel.TextAlign = "MiddleCenter"
    $OldPassLabel.BackColor = "Transparent"
    $OldPassLabel.ForeColor = "Black"
    $OldPassLabel.Add_Click({
        $OldPassLabel.Visible = $false
        $OldPasswordTextBox.Focus()
    })
    $OldPasswordTextBox.Controls.Add($OldPassLabel)

    $InfoButton = New-Object System.Windows.Forms.Label
    $InfoButton.Location = New-Object System.Drawing.Size($($UsernameTextbox.Width - $UsernameTextbox.Height))
    $InfoButton.Size = New-Object System.Drawing.Size(20, $UsernameTextbox.Height)
    $InfoButton.Font = New-Object System.Drawing.Font("Calibri Light",13,[System.Drawing.FontStyle]::Bold)
    if (!(Test-Path variable:$UserinfoImage)){
        $InfoButton.Image = $UserinfoImage
    } else {
        $InfoButton.Text = " I"
    }
    $InfoButton.ForeColor = "Blue"
    $InfoButton.FlatStyle = "Flat"
    $InfoButton.Cursor = "Hand"
    $InfoButton.Visible = $false
    $InfoButton.Add_Click({
        $RoleButton.ForeColor = "Black"
        $RoleButton.Text = ""
        if (!(Test-Path variable:$userrolesImage)){
            $RoleButton.Image = $userrolesImage
        } else {
            $RoleButton.Text = "R"
        }
        if($InfoButton.Text -ne "⤴") {
            fetch_info
            $InfoButton.Image = $null
            $InfoButton.Text = "⤴";
            $UserGrid.Visible = $UserRolesGrid.Visible = $false
            $UserPropertiesGrid.Visible = $true
            $SearchRoleTextBox.Focus()
            $ToolTip.SetToolTip($InfoButton, "Return")
        } else {
            $InfoButton.Text = ""
            if (!(Test-Path variable:$UserinfoImage)){
                $InfoButton.Image = $UserinfoImage
            } else {
                $InfoButton.Text = " I"
            }

            $ToolTip.SetToolTip($InfoButton, "Show user info")
            $UserPropertiesGrid.Visible = $false;
            if ($RoleButton.Text -ne "⤴") {$UserRolesGrid.Visible = $false; $UserGrid.Visible = $true} else {$UserGrid.Visible = $false; $UserRolesGrid.Visible = $true}
            $SearchUserTextBox.Focus()
        }
    })
    $UsernameTextbox.Controls.Add($InfoButton)
    
    $RoleButton = New-Object System.Windows.Forms.Label
    $RoleButton.Location = New-Object System.Drawing.Size(1,-1)
    $RoleButton.Size = New-Object System.Drawing.Size(22,$SearchRoleTextBox.Height)
    $RoleButton.Font = New-Object System.Drawing.Font("Calibri Light",13,[System.Drawing.FontStyle]::Bold)
    $RoleButton.FlatStyle = "Flat"
    $RoleButton.Visible = $false
    $RoleButton.ForeColor = "Blue"
    $RoleButton.Cursor = "Hand"
    if (!(Test-Path variable:$userrolesImage)){
        $RoleButton.Image = $userrolesImage
    } else {
        $RoleButton.Text = "R"
    }
    $RoleButton.BackColor = "Transparent"
    $RoleButton.Add_Click({
        $InfoButton.Text = ""
        if (!(Test-Path variable:$UserinfoImage)){
            $InfoButton.Image = $UserinfoImage
        } else {
            $InfoButton.Text = " I"
        }
        if($RoleButton.Text -ne "⤴") {
            memberof
            $RoleButton.ForeColor = "Blue";
            $RoleButton.Text = "⤴";
            $RoleButton.Image = $null
            $SearchRoleTextBox.Focus()
            $ToolTip.SetToolTip($RoleButton, "Return")
        } else {
            $RoleButton.ForeColor = "Black"
            $RoleButton.Text = ""
            if (!(Test-Path variable:$userrolesImage)){
                $RoleButton.Image = $userrolesImage
            } else {
                $RoleButton.Text = "R"
            }
            $UserRolesGrid.Visible = $false;
            $UserGrid.Visible = $true
            $ToolTip.SetToolTip($RoleButton, "Show user roles")
            $SearchUserTextBox.Focus()
        }
        $BlockLabel.Text = ""
    })
    $UsernameTextbox.Controls.Add($RoleButton)

    $AdminUpdate = New-Object System.Windows.Forms.Label
    $AdminUpdate.Size = New-Object System.Drawing.Size(20, $UsernameTextbox.Height)
    if (!(Test-Path variable:$GearImage)){
        $AdminUpdate.Image = $GearhImage
        $AdminUpdate.Location = New-Object System.Drawing.Size($($UserTypeCheckBox.Width - 23), 0)
    } else {
        $AdminUpdate.Text = "⚙"
        $AdminUpdate.Location = New-Object System.Drawing.Size($($UserTypeCheckBox.Width - 22), 5)
    }
    $AdminUpdate.Image = $GearImage
    $AdminUpdate.Font = New-Object System.Drawing.Font("Calibri",11,[System.Drawing.FontStyle]::Bold)
    $AdminUpdate.Cursor = "Hand"
    $AdminUpdate.FlatStyle = "Flat"
    $AdminUpdate.BackColor = "Transparent"
    $AdminUpdate.Visible = $true
    $AdminUpdate.Add_Click({
        $SetAdminPrefixSuffixGroup.Visible = $($AdminUpdate.BackColor -eq "Transparent")
        $SearchEnterButton.Visible = $($AdminUpdate.BackColor -ne "Transparent")
        $SearchLabel.Visible = $UserTypeCheckBox.Visible = $SearchUserTextBox.Visible = !$($AdminUpdate.BackColor -eq "Transparent")
        if ($AdminUpdate.BackColor -eq "Transparent") {$AdminUpdate.BackColor = "Yellow"} else {$AdminUpdate.BackColor = "Transparent"}
    })
    $UserTypeCheckBox.Controls.Add($AdminUpdate)

    $AdminUpdateReturn = New-Object System.Windows.Forms.Label
    $AdminUpdateReturn.Location = New-Object System.Drawing.Size($($AdminTextBox.Width - 22), 1)
    $AdminUpdateReturn.Size = New-Object System.Drawing.Size(20, $UsernameTextbox.Height)
    $AdminUpdateReturn.Text = "⤴"
    $AdminUpdateReturn.Font = New-Object System.Drawing.Font("Calibri",13,[System.Drawing.FontStyle]::Bold)
    $AdminUpdateReturn.Cursor = "Hand"
    $AdminUpdateReturn.FlatStyle = "Flat"
    $AdminUpdateReturn.BackColor = "Transparent"
    $AdminUpdateReturn.Visible = $true
    $AdminUpdateReturn.Add_Click({
        $SetAdminPrefixSuffixGroup.Visible = $($AdminUpdate.BackColor -eq "Transparent")
        $SearchEnterButton.Visible = $($AdminUpdate.BackColor -ne "Transparent")
        $SearchLabel.Visible = $UserTypeCheckBox.Visible = $SearchUserTextBox.Visible = !$($AdminUpdate.BackColor -eq "Transparent")
        if ($AdminUpdate.BackColor -eq "Transparent") {$AdminUpdate.BackColor = "Yellow"} else {$AdminUpdate.BackColor = "Transparent"}
    })
    $AdminTextBox.Controls.Add($AdminUpdateReturn)
    
    $AdminUpdateClear = New-Object System.Windows.Forms.Label
    $AdminUpdateClear.Location = New-Object System.Drawing.Size(0, $UserTypeCheckBox.Location.Y)
    $AdminUpdateClear.Size = New-Object System.Drawing.Size(20, $UsernameTextbox.Height)
    $AdminUpdateClear.Text = "✘"
    $AdminUpdateClear.Font = New-Object System.Drawing.Font("Calibri",11,[System.Drawing.FontStyle]::Bold)
    $AdminUpdateClear.Cursor = "Hand"
    $AdminUpdateClear.ForeColor = "Red"
    $AdminUpdateClear.FlatStyle = "Flat"
    $AdminUpdateClear.BackColor = "Transparent"
    $AdminUpdateClear.Visible = $AdminTextBox.Text.Length -gt 0
    $AdminUpdateClear.Add_Click({
        $AdminTextBox.Text = ""
    })
    $AdminTextBox.Controls.Add($AdminUpdateClear)
    
    $AdminUpdateSave = New-Object System.Windows.Forms.Label
    $AdminUpdateSave.Location = New-Object System.Drawing.Size($($AdminUpdateReturn.Left - 20), $UserTypeCheckBox.Location.Y)
    $AdminUpdateSave.Size = New-Object System.Drawing.Size(20, $UsernameTextbox.Height)
    $AdminUpdateSave.Text = "✔"
    $AdminUpdateSave.Cursor = "Hand"
    $AdminUpdateSave.FlatStyle = "Flat"
    $AdminUpdateSave.BackColor = "Transparent"
    $AdminUpdateSave.Visible = $false
    $AdminUpdateSave.Add_Click({
        set-admin-prefix
        $AdminUpdateSave.Visible = $false
    })
    $AdminTextBox.Controls.Add($AdminUpdateSave)

    $WhiteBrush = New-Object Drawing.SolidBrush White
    $BlackBrush = New-Object Drawing.SolidBrush Black
    $ToolTip = New-Object System.Windows.Forms.ToolTip
    $ToolTip.SetToolTip($SearchUserTextBox, "Search user(s) (press enter to search actively)")
    $ToolTip.SetToolTip($AdminUpdate, "Set admin prefix/suffix")
    $ToolTip.SetToolTip($AdminUpdateReturn, "Return")
    $ToolTip.SetToolTip($AdminUpdateClear, "Clear admin prefix/suffix input")
    $ToolTip.SetToolTip($AdminUpdateSave, "Save admin prefix/suffix")
    $ToolTip.SetToolTip($DisplayButton, "Show (display)name")
    $ToolTip.SetToolTip($InfoButton, "Show user info")
    $ToolTip.SetToolTip($RestoreRadioButton, "Select restore password option")
    $ToolTip.SetToolTip($ResetRadioButton, "Select reset password option")
    $ToolTip.SetToolTip($ClearSearch, "Clear search field")
    $ToolTip.SetToolTip($SearchEnterButton, "Search user(s)")
    $ToolTip.SetToolTip($SaveButton, "Submit")
    $ToolTip.SetToolTip($OldPasswordTextBox, "Enter old password")
    $ToolTip.SetToolTip($NewPasswordTextBox, "Enter new password")
    $ToolTip.SetToolTip($SearchRoleTextBox, "Search role(s) (press enter to search actively)")
    $ToolTip.SetToolTip($ReloadRoles, "Reload roles")
    $ToolTip.SetToolTip($AddRole, "Add role(s)")
    $ToolTip.SetToolTip($RemoveRole, "Remove role(s)")
    $ToolTip.SetToolTip($CheckBoxButton, "Filter user properties")
    $ToolTip.SetToolTip($SaveFilterSetting, "Save current filter")
    $ToolTip.SetToolTip($LeftRadioButton, "Prefix: '$($AdminTextBox.Text)Username'")
    $ToolTip.SetToolTip($RightRadioButton, "Suffix: 'Username$($AdminTextBox.Text)'")
    $ToolTip.SetToolTip($CopyButton, "Copy value")
    $ToolTip.SetToolTip($PasteButton, "Paste value")
    $ToolTip.SetToolTip($RoleButton, "Show user roles")
    $ToolTip.SetToolTip($ShowCategory, "Show/hide category")
    $ToolTip.SetToolTip($UserTypeCheckBox, "Filter on admins")

    $ToolTip.OwnerDraw = $true
    $ToolTip_Draw=[System.Windows.Forms.DrawToolTipEventHandler]{
            $fontstyle = New-Object System.Drawing.Font('Calibri Light', 10, [System.Drawing.FontStyle]::Regular)
            $format = [System.Drawing.StringFormat]::GenericTypographic
            $format.LineAlignment = [System.Drawing.StringAlignment]::Center
            $format.Alignment = [System.Drawing.StringAlignment]::Center        
            $_.Graphics.FillRectangle($BlackBrush, $_.Bounds)
            $_.Graphics.DrawString($_.ToolTipText, $fontstyle, $WhiteBrush, ($_.Bounds.X + ($_.Bounds.Width/2)), ($_.Bounds.Y + ($_.Bounds.Height/2)), $format)         
    }
    $ToolTip.Add_Draw($ToolTip_Draw)
    $Add_FormClosed={
        try{$ToolTip.Remove_Draw($ToolTip_Draw)} catch { Out-Null }
    }
    $form.Add_Shown({$form.Activate()})
    [void] $form.ShowDialog()
}
start-script
